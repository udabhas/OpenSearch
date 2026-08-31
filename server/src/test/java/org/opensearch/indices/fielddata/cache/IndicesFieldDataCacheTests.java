/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.indices.fielddata.cache;

import org.apache.lucene.document.Document;
import org.apache.lucene.index.DirectoryReader;
import org.apache.lucene.index.IndexReader;
import org.apache.lucene.index.IndexWriter;
import org.apache.lucene.index.LeafReaderContext;
import org.apache.lucene.store.Directory;
import org.apache.lucene.util.Accountable;
import org.opensearch.common.settings.Settings;
import org.opensearch.core.index.Index;
import org.opensearch.core.index.shard.ShardId;
import org.opensearch.index.fielddata.FielddataLoadContext;
import org.opensearch.index.fielddata.IndexFieldData;
import org.opensearch.index.fielddata.IndexFieldDataCache;
import org.opensearch.index.fielddata.LeafFieldData;
import org.opensearch.indices.fielddata.cache.IndicesFieldDataCache.IndexFieldCache;
import org.opensearch.indices.fielddata.cache.IndicesFieldDataCache.Key;
import org.opensearch.test.OpenSearchTestCase;

import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class IndicesFieldDataCacheTests extends OpenSearchTestCase {

    /**
     * Reproduces the fielddata leak from the clear-index path (clear-cache API, fielddata settings
     * change, index close): an entry marked for cleanup is silently skipped when a concurrent cache
     * hit promotes it to the head of the LRU list after the sweep's cursor has already passed the
     * head. Because {@link IndicesFieldDataCache#clear()} consumes the marks before scanning, the
     * skipped entry is never revisited and leaks. The promotion is triggered deterministically from
     * the removal listener of the first swept entry, mimicking a search touching the cache while the
     * cleaner runs. This test fails if the sweep iterates the live {@code Cache#keys()} LRU view and
     * passes with the point-in-time {@code Cache#keysSnapshot()}.
     */
    public void testClearIndexIsNotDefeatedByLruPromotionMidSweep() throws Exception {
        final AtomicReference<Runnable> onFirstRemoval = new AtomicReference<>();
        final IndicesFieldDataCache fdCache = newFieldDataCache(onFirstRemoval);
        try (Directory directory = newDirectory(); IndexWriter writer = new IndexWriter(directory, newIndexWriterConfig())) {
            writer.addDocument(new Document());
            try (DirectoryReader reader = DirectoryReader.open(writer)) {
                IndexReader.CacheKey readerKey = reader.leaves().get(0).reader().getCoreCacheHelper().getKey();
                Index target = new Index("target", "target-uuid");
                Index other = new Index("other", "other-uuid");
                IndexFieldCache targetField1 = buildIndexFieldCache(fdCache, target, "f1");
                IndexFieldCache targetField2 = buildIndexFieldCache(fdCache, target, "f2");
                IndexFieldCache otherField = buildIndexFieldCache(fdCache, other, "f1");

                Key tailTargetKey = new Key(targetField1, readerKey, null);
                Key fillerKey = new Key(otherField, readerKey, null);
                Key headTargetKey = new Key(targetField2, readerKey, null);
                Accountable value = () -> 10;

                // LRU order after insertion, head to tail: headTargetKey, fillerKey, tailTargetKey
                fdCache.getCache().put(tailTargetKey, value);
                fdCache.getCache().put(fillerKey, value);
                fdCache.getCache().put(headTargetKey, value);

                // While the sweep removes its first entry, a concurrent search hits the
                // not-yet-visited target entry, relinking it at the head of the LRU list
                // behind the sweep's cursor.
                onFirstRemoval.set(() -> fdCache.getCache().get(tailTargetKey));

                fdCache.clear(target);
                fdCache.clear();

                assertEquals(1, fdCache.getCache().count());
                for (Key key : fdCache.getCache().keysSnapshot()) {
                    assertEquals(other, key.indexCache.index);
                }
            }
        } finally {
            fdCache.close();
        }
    }

    public void testExceptionWhileRemovingKeyDoesNotAbortSweep() throws Exception {
        final AtomicBoolean hasThrownException = new AtomicBoolean();
        final IndicesFieldDataCache fdCache = new IndicesFieldDataCache(Settings.EMPTY, new IndexFieldDataCache.Listener() {
        }, null, null) {
            @Override
            void invalidateKey(Key key) {
                if (hasThrownException.compareAndSet(false, true)) {
                    throw new UnsupportedOperationException("uh oh!");
                }
                super.invalidateKey(key);
            }
        };

        try (Directory directory = newDirectory(); IndexWriter writer = new IndexWriter(directory, newIndexWriterConfig())) {
            writer.addDocument(new Document());
            try (DirectoryReader reader = DirectoryReader.open(writer)) {
                IndexReader.CacheKey readerKey = reader.leaves().get(0).reader().getCoreCacheHelper().getKey();
                Index target = new Index("target", "target-uuid");
                IndexFieldCache targetField1 = buildIndexFieldCache(fdCache, target, "f1");
                IndexFieldCache targetField2 = buildIndexFieldCache(fdCache, target, "f2");
                Accountable value = () -> 10;

                fdCache.getCache().put(new Key(targetField1, readerKey, null), value);
                fdCache.getCache().put(new Key(targetField2, readerKey, null), value);

                fdCache.clear(target);
                fdCache.clear();

                assertTrue(hasThrownException.get());
                assertEquals(1, fdCache.getCache().count());
            }
        } finally {
            fdCache.close();
        }
    }

    /**
     * The load path must tell a Directory that a field data build is in progress. Both halves matter: set
     * for the duration of {@code loadDirect}, which is the uninversion that produces every derived input a
     * build makes, and cleared afterwards, because search threads are pooled and a leaked marker would make
     * the next unrelated request bypass the buffer pool.
     */
    public void testLoadMarksTheThreadForTheDurationOfLoadDirect() throws Exception {
        final IndicesFieldDataCache fdCache = new IndicesFieldDataCache(Settings.EMPTY, new IndexFieldDataCache.Listener() {
        }, null, null);
        try (Directory directory = newDirectory(); IndexWriter writer = new IndexWriter(directory, newIndexWriterConfig())) {
            writer.addDocument(new Document());
            try (DirectoryReader reader = DirectoryReader.open(writer)) {
                LeafReaderContext leaf = reader.leaves().get(0);
                IndexFieldCache cache = buildIndexFieldCache(fdCache, new Index("idx", "idx-uuid"), "f1");

                assertFalse("marker must not be set before the load", FielddataLoadContext.isFielddataLoad());

                final AtomicBoolean markedInsideLoadDirect = new AtomicBoolean(false);
                cache.load(leaf, fieldDataThatRecordsTheMarker(markedInsideLoadDirect));

                assertTrue("loadDirect must run with the thread marked", markedInsideLoadDirect.get());
                assertFalse("marker must be cleared once the build returns", FielddataLoadContext.isFielddataLoad());
            }
        } finally {
            fdCache.close();
        }
    }

    /** A build that throws must still leave the marker clear, hence the finally rather than a plain clear. */
    public void testMarkerIsClearedWhenLoadDirectThrows() throws Exception {
        final IndicesFieldDataCache fdCache = new IndicesFieldDataCache(Settings.EMPTY, new IndexFieldDataCache.Listener() {
        }, null, null);
        try (Directory directory = newDirectory(); IndexWriter writer = new IndexWriter(directory, newIndexWriterConfig())) {
            writer.addDocument(new Document());
            try (DirectoryReader reader = DirectoryReader.open(writer)) {
                LeafReaderContext leaf = reader.leaves().get(0);
                IndexFieldCache cache = buildIndexFieldCache(fdCache, new Index("idx", "idx-uuid"), "f1");

                IndexFieldData<?> exploding = mock(IndexFieldData.class);
                when(exploding.loadDirect(leaf)).thenThrow(new IllegalStateException("uninversion blew up"));

                expectThrows(Exception.class, () -> cache.load(leaf, exploding));
                assertFalse("a failed build must not leak the marker", FielddataLoadContext.isFielddataLoad());
            }
        } finally {
            fdCache.close();
        }
    }

    /**
     * A cache HIT performs no reads, so it must not mark the thread - only the miss that actually uninverts
     * does. Guards the placement of the marker inside computeIfAbsent rather than around the whole method.
     */
    public void testCacheHitDoesNotMarkTheThread() throws Exception {
        final IndicesFieldDataCache fdCache = new IndicesFieldDataCache(Settings.EMPTY, new IndexFieldDataCache.Listener() {
        }, null, null);
        try (Directory directory = newDirectory(); IndexWriter writer = new IndexWriter(directory, newIndexWriterConfig())) {
            writer.addDocument(new Document());
            try (DirectoryReader reader = DirectoryReader.open(writer)) {
                LeafReaderContext leaf = reader.leaves().get(0);
                IndexFieldCache cache = buildIndexFieldCache(fdCache, new Index("idx", "idx-uuid"), "f1");

                final AtomicBoolean firstMarked = new AtomicBoolean(false);
                cache.load(leaf, fieldDataThatRecordsTheMarker(firstMarked));
                assertTrue("the miss must mark", firstMarked.get());

                final AtomicBoolean secondMarked = new AtomicBoolean(false);
                cache.load(leaf, fieldDataThatRecordsTheMarker(secondMarked));
                assertFalse("a cache hit reads nothing, so it must not mark", secondMarked.get());
                assertFalse(FielddataLoadContext.isFielddataLoad());
            }
        } finally {
            fdCache.close();
        }
    }

    @SuppressWarnings("unchecked")
    private static IndexFieldData<LeafFieldData> fieldDataThatRecordsTheMarker(AtomicBoolean seen) throws Exception {
        IndexFieldData<LeafFieldData> indexFieldData = mock(IndexFieldData.class);
        LeafFieldData leafFieldData = mock(LeafFieldData.class);
        when(leafFieldData.ramBytesUsed()).thenReturn(10L);
        when(indexFieldData.loadDirect(any(LeafReaderContext.class))).thenAnswer(invocation -> {
            seen.set(FielddataLoadContext.isFielddataLoad());
            return leafFieldData;
        });
        return indexFieldData;
    }

    private IndicesFieldDataCache newFieldDataCache(AtomicReference<Runnable> onFirstRemoval) {
        return new IndicesFieldDataCache(Settings.EMPTY, new IndexFieldDataCache.Listener() {
            @Override
            public void onRemoval(ShardId shardId, String fieldName, boolean wasEvicted, long sizeInBytes) {
                Runnable hook = onFirstRemoval.getAndSet(null);
                if (hook != null) {
                    hook.run();
                }
            }
        }, null, null);
    }

    private IndexFieldCache buildIndexFieldCache(IndicesFieldDataCache fdCache, Index index, String fieldName) {
        return (IndexFieldCache) fdCache.buildIndexFieldDataCache(new IndexFieldDataCache.Listener() {
        }, index, fieldName);
    }
}
