/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.index.shard;

import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.message.ParameterizedMessage;
import org.apache.lucene.index.CorruptIndexException;
import org.apache.lucene.store.DataAccessHint;
import org.apache.lucene.store.Directory;
import org.apache.lucene.store.FilterDirectory;
import org.apache.lucene.store.IOContext;
import org.opensearch.action.support.GroupedActionListener;
import org.opensearch.cluster.metadata.CryptoMetadata;
import org.opensearch.common.logging.Loggers;
import org.opensearch.common.util.UploadListener;
import org.opensearch.core.action.ActionListener;
import org.opensearch.index.store.RemoteSegmentStoreDirectory;
import org.opensearch.index.store.RemoteSyncListener;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.function.Function;

/**
 * The service essentially acts as a bridge between local segment storage and remote storage,
 * ensuring efficient and reliable segment synchronization while providing comprehensive monitoring and error handling.
 */
public class RemoteStoreUploaderService implements RemoteStoreUploader {

    /**
     * Context for the segment-upload reads. Every file is streamed to the remote store exactly once,
     * forwards-only, and never re-read, so the access pattern is declared with
     * {@link DataAccessHint#SEQUENTIAL} rather than left as the bare {@link IOContext#DEFAULT} (whose
     * implied advice is RANDOM).
     *
     * <p>Deliberately NOT {@link IOContext#READONCE}: multipart upload clones/slices this input once per
     * part, and both {@code RemoteDirectory.uploadBlob} and {@code DataFormatAwareRemoteDirectory.uploadBlob}
     * assert against a READONCE context for exactly that reason. A hinted DEFAULT is neither reference- nor
     * value-equal to READONCE, so those assertions still hold.
     *
     * <p>Inert for the stock store types — nothing in the server reads {@code hints()}, and
     * {@code MMapDirectory}'s read-advice function is not installed by {@code FsDirectoryFactory} — so this
     * is a no-op unless a directory implementation opts in to consuming the hint.
     */
    private static final IOContext SEQUENTIAL_UPLOAD_CONTEXT = IOContext.DEFAULT.withHints(DataAccessHint.SEQUENTIAL);

    private final Logger logger;

    private final IndexShard indexShard;
    private final Directory storeDirectory;
    private final RemoteSegmentStoreDirectory remoteDirectory;
    private final List<RemoteSyncListener> syncListeners = new ArrayList<>();

    public RemoteStoreUploaderService(IndexShard indexShard, Directory storeDirectory, RemoteSegmentStoreDirectory remoteDirectory) {
        logger = Loggers.getLogger(getClass(), indexShard.shardId());
        this.indexShard = indexShard;
        this.storeDirectory = storeDirectory;
        this.remoteDirectory = remoteDirectory;
        // One-time chain walk at construction — register the sync listener from the directory stack
        registerSyncListenersFromDirectory(storeDirectory);
    }

    /**
     * Registers a listener to be notified after each file is synced to remote.
     *
     * @param listener the listener to register
     */
    public void addSyncListener(RemoteSyncListener listener) {
        if (listener != null) {
            syncListeners.add(listener);
        }
    }

    /**
     * Walks the directory chain once to find and register the first {@link RemoteSyncListener}.
     */
    private void registerSyncListenersFromDirectory(Directory dir) {
        Directory current = dir;
        while (current != null) {
            if (current instanceof RemoteSyncListener) {
                syncListeners.add((RemoteSyncListener) current);
                return;
            }
            if (current instanceof FilterDirectory) {
                current = ((FilterDirectory) current).getDelegate();
            } else {
                break;
            }
        }
    }

    @Override
    public void uploadSegments(
        Collection<String> localSegments,
        Map<String, Long> localSegmentsSizeMap,
        ActionListener<Void> listener,
        Function<Map<String, Long>, UploadListener> uploadListenerFunction,
        boolean isLowPriorityUpload,
        CryptoMetadata cryptoMetadata
    ) {
        if (localSegments.isEmpty()) {
            logger.debug("No new segments to upload in uploadNewSegments");
            listener.onResponse(null);
            return;
        }

        logger.debug("Effective new segments files to upload {}", localSegments);
        ActionListener<Collection<Void>> mappedListener = ActionListener.map(listener, resp -> null);
        GroupedActionListener<Void> batchUploadListener = new GroupedActionListener<>(mappedListener, localSegments.size());

        for (String localSegment : localSegments) {
            // Initializing listener here to ensure that the stats increment operations are thread-safe
            UploadListener statsListener = uploadListenerFunction.apply(localSegmentsSizeMap);
            ActionListener<Void> aggregatedListener = ActionListener.wrap(resp -> {
                statsListener.onSuccess(localSegment);
                batchUploadListener.onResponse(resp);
                // Once uploaded to Remote, local files become eligible for eviction from FileCache
                notifyAfterSyncToRemote(localSegment);
            }, ex -> {
                logger.warn(() -> new ParameterizedMessage("Exception: [{}] while uploading segment files", ex), ex);
                if (ex instanceof CorruptIndexException) {
                    indexShard.failShard(ex.getMessage(), ex);
                }
                statsListener.onFailure(localSegment);
                batchUploadListener.onFailure(ex);
            });
            statsListener.beforeUpload(localSegment);
            remoteDirectory.copyFrom(
                storeDirectory,
                localSegment,
                SEQUENTIAL_UPLOAD_CONTEXT,
                aggregatedListener,
                isLowPriorityUpload,
                cryptoMetadata
            );
        }
    }

    private void notifyAfterSyncToRemote(String file) {
        for (RemoteSyncListener listener : syncListeners) {
            listener.afterSyncToRemote(file);
        }
    }
}
