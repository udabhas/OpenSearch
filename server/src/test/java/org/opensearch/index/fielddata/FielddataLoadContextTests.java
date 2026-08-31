/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.index.fielddata;

import org.opensearch.test.OpenSearchTestCase;

import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

public class FielddataLoadContextTests extends OpenSearchTestCase {

    @Override
    public void tearDown() throws Exception {
        // A leaked marker would make every later test on this thread observe a field data build, so make
        // the leak a failure here rather than an unexplained result somewhere else.
        boolean leaked = FielddataLoadContext.isFielddataLoad();
        while (FielddataLoadContext.isFielddataLoad()) {
            FielddataLoadContext.clearFielddataLoad();
        }
        super.tearDown();
        assertFalse("test leaked the field data marker onto a pooled thread", leaked);
    }

    public void testUnsetByDefault() {
        assertFalse(FielddataLoadContext.isFielddataLoad());
    }

    public void testMarkThenClear() {
        FielddataLoadContext.markFielddataLoad();
        assertTrue(FielddataLoadContext.isFielddataLoad());
        FielddataLoadContext.clearFielddataLoad();
        assertFalse(FielddataLoadContext.isFielddataLoad());
    }

    /**
     * The reason this is a depth counter and not a boolean: a nested load must not clear the marker while
     * the outer build is still running. With a boolean the inner clear ends the outer scope early and the
     * rest of the outer build silently loses the bypass.
     */
    public void testNestedLoadDoesNotClearOuterMarker() {
        FielddataLoadContext.markFielddataLoad();
        FielddataLoadContext.markFielddataLoad();
        assertTrue(FielddataLoadContext.isFielddataLoad());

        FielddataLoadContext.clearFielddataLoad();
        assertTrue("inner clear must not end the outer build", FielddataLoadContext.isFielddataLoad());

        FielddataLoadContext.clearFielddataLoad();
        assertFalse(FielddataLoadContext.isFielddataLoad());
    }

    public void testDeeplyNestedIsBalanced() {
        final int depth = randomIntBetween(3, 32);
        for (int i = 0; i < depth; i++) {
            FielddataLoadContext.markFielddataLoad();
            assertTrue(FielddataLoadContext.isFielddataLoad());
        }
        for (int i = 0; i < depth - 1; i++) {
            FielddataLoadContext.clearFielddataLoad();
            assertTrue("still inside the outermost build at depth " + (depth - 1 - i), FielddataLoadContext.isFielddataLoad());
        }
        FielddataLoadContext.clearFielddataLoad();
        assertFalse(FielddataLoadContext.isFielddataLoad());
    }

    /** An unbalanced clear must not drive the depth negative, or the next mark would not register. */
    public void testUnmatchedClearIsANoOp() {
        FielddataLoadContext.clearFielddataLoad();
        FielddataLoadContext.clearFielddataLoad();
        assertFalse(FielddataLoadContext.isFielddataLoad());

        FielddataLoadContext.markFielddataLoad();
        assertTrue("a mark after unmatched clears must still register", FielddataLoadContext.isFielddataLoad());
        FielddataLoadContext.clearFielddataLoad();
        assertFalse(FielddataLoadContext.isFielddataLoad());
    }

    /** The marker is per thread, so a build on one thread must be invisible to a search on another. */
    public void testMarkerIsNotVisibleToAnotherThread() throws Exception {
        final CountDownLatch marked = new CountDownLatch(1);
        final CountDownLatch observed = new CountDownLatch(1);
        final AtomicBoolean seenOnOtherThread = new AtomicBoolean(true);

        Thread other = new Thread(() -> {
            try {
                marked.await(10, TimeUnit.SECONDS);
                seenOnOtherThread.set(FielddataLoadContext.isFielddataLoad());
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            } finally {
                observed.countDown();
            }
        }, "fielddata-marker-other");

        other.start();
        FielddataLoadContext.markFielddataLoad();
        try {
            marked.countDown();
            assertTrue(observed.await(10, TimeUnit.SECONDS));
            assertFalse("marker must not be visible to another thread", seenOnOtherThread.get());
            assertTrue("marker must still be set on the marking thread", FielddataLoadContext.isFielddataLoad());
        } finally {
            FielddataLoadContext.clearFielddataLoad();
            other.join(TimeUnit.SECONDS.toMillis(10));
        }
    }

    /**
     * The contract that matters for a pooled search thread: a build that throws must still leave the marker
     * clear, otherwise the next unrelated request on that thread bypasses the buffer pool.
     */
    public void testClearInFinallySurvivesAnException() {
        expectThrows(IllegalStateException.class, () -> {
            FielddataLoadContext.markFielddataLoad();
            try {
                throw new IllegalStateException("uninversion blew up");
            } finally {
                FielddataLoadContext.clearFielddataLoad();
            }
        });
        assertFalse("an exception during the build must not leak the marker", FielddataLoadContext.isFielddataLoad());
    }

    /** Each thread carries its own depth, so concurrent builds cannot interfere. */
    public void testConcurrentThreadsKeepIndependentDepth() throws Exception {
        final int threads = randomIntBetween(2, 8);
        final CountDownLatch start = new CountDownLatch(1);
        final CountDownLatch done = new CountDownLatch(threads);
        final AtomicBoolean failed = new AtomicBoolean(false);

        for (int i = 0; i < threads; i++) {
            final int depth = i + 1;
            new Thread(() -> {
                try {
                    start.await(10, TimeUnit.SECONDS);
                    for (int d = 0; d < depth; d++) {
                        FielddataLoadContext.markFielddataLoad();
                    }
                    if (FielddataLoadContext.isFielddataLoad() == false) {
                        failed.set(true);
                    }
                    for (int d = 0; d < depth; d++) {
                        FielddataLoadContext.clearFielddataLoad();
                    }
                    if (FielddataLoadContext.isFielddataLoad()) {
                        failed.set(true);
                    }
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    failed.set(true);
                } finally {
                    done.countDown();
                }
            }, "fielddata-marker-" + i).start();
        }

        start.countDown();
        assertTrue(done.await(30, TimeUnit.SECONDS));
        assertFalse("a thread observed another thread's depth", failed.get());
        assertFalse(FielddataLoadContext.isFielddataLoad());
    }
}
