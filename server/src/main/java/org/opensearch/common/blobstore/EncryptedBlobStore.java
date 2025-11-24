/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.common.blobstore;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.cluster.metadata.CryptoMetadata;
import org.opensearch.cluster.metadata.RepositoryMetadata;
import org.opensearch.common.crypto.CryptoHandler;
import org.opensearch.crypto.CryptoHandlerRegistry;
import org.opensearch.crypto.CryptoRegistryException;
import org.opensearch.repositories.blobstore.BlobStoreRepository;

import java.io.IOException;
import java.util.Map;

/**
 * The EncryptedBlobStore is a decorator class that wraps an existing BlobStore and provides encryption and decryption
 * capabilities for the stored data. It uses a CryptoManager to handle encryption and decryption operations based on
 * the provided CryptoMetadata. The EncryptedBlobStore ensures that all data written to and read from the underlying
 * BlobStore is encrypted and decrypted transparently.
 */
public class EncryptedBlobStore implements BlobStore {

    private static final Logger logger = LogManager.getLogger(EncryptedBlobStore.class);

    private final BlobStore blobStore;
    private final CryptoHandler<?, ?> cryptoHandler;
    private final CryptoMetadata repositoryCryptoMetadata;  // Store for merging with index metadata

    /**
     * Constructs an EncryptedBlobStore that wraps the provided BlobStore with encryption capabilities based on the
     * given CryptoMetadata.
     *
     * @param blobStore     The underlying BlobStore to be wrapped and used for storing encrypted data.
     * @param cryptoMetadata The CryptoMetadata containing information about the key provider and settings for encryption.
     * @throws CryptoRegistryException If the CryptoManager is not found during encrypted BlobStore creation.
     */
    public EncryptedBlobStore(BlobStore blobStore, CryptoMetadata cryptoMetadata) {
        CryptoHandlerRegistry cryptoHandlerRegistry = CryptoHandlerRegistry.getInstance();
        assert cryptoHandlerRegistry != null : "CryptoManagerRegistry is not initialized";
        this.cryptoHandler = cryptoHandlerRegistry.fetchCryptoHandler(cryptoMetadata);
        if (cryptoHandler == null) {
            throw new CryptoRegistryException(
                cryptoMetadata.keyProviderName(),
                cryptoMetadata.keyProviderType(),
                "Crypto manager not found during encrypted blob store creation."
            );
        }
        this.blobStore = blobStore;
        this.repositoryCryptoMetadata = cryptoMetadata;
    }

    /**
     * Retrieves a BlobContainer from the underlying BlobStore based on the provided BlobPath. The returned BlobContainer
     * is wrapped in an EncryptedBlobContainer to enable transparent encryption and decryption of data.
     *
     * @param path The BlobPath specifying the location of the BlobContainer.
     * @return An EncryptedBlobContainer wrapping the BlobContainer retrieved from the underlying BlobStore.
     */
    @Override
    public BlobContainer blobContainer(BlobPath path) {
        logger.info("inside blobContainer for cluster level with path = {}", path);
        BlobContainer blobContainer = blobStore.blobContainer(path);
        if (blobContainer instanceof AsyncMultiStreamBlobContainer) {
            return new AsyncMultiStreamEncryptedBlobContainer<>((AsyncMultiStreamBlobContainer) blobContainer, cryptoHandler);
        }
        return new EncryptedBlobContainer<>(blobContainer, cryptoHandler);
    }

    // overloadded method to get blob container with the new crypto metadata
    public BlobContainer blobContainer(BlobPath path, CryptoMetadata cryptoMetadata) {
        logger.info("inside blobContainer for index level with path = {}, cryptoMetadata = {}", path, cryptoMetadata);
        
        // Merge index metadata with repository metadata for context merging
        CryptoMetadata merged = (cryptoMetadata != null) ? mergeCryptoMetadata(cryptoMetadata) : this.repositoryCryptoMetadata;
        
        CryptoHandlerRegistry cryptoHandlerRegistry = CryptoHandlerRegistry.getInstance();
        assert cryptoHandlerRegistry != null : "CryptoManagerRegistry is not initialized";
        CryptoHandler IndexCryptoHandler = cryptoHandlerRegistry.fetchCryptoHandler(merged);

        BlobContainer blobContainer = blobStore.blobContainer(path);
        if (blobContainer instanceof AsyncMultiStreamBlobContainer) {
            return new AsyncMultiStreamEncryptedBlobContainer<>((AsyncMultiStreamBlobContainer) blobContainer, IndexCryptoHandler);
        }
        return new EncryptedBlobContainer<>(blobContainer, IndexCryptoHandler);
    }

    /**
     * Reoload blobstore metadata
     * @param repositoryMetadata new repository metadata
     */
    @Override
    public void reload(RepositoryMetadata repositoryMetadata) {
        blobStore.reload(repositoryMetadata);
    }

    /**
     * Retrieves statistics about the BlobStore. Delegates the call to the underlying BlobStore's stats() method.
     *
     * @return A map containing statistics about the BlobStore.
     */
    @Override
    public Map<String, Long> stats() {
        return blobStore.stats();
    }

    /**
     * Retrieves extended statistics about the BlobStore. Delegates the call to the underlying BlobStore's extendedStats() method.
     *
     * @return A map containing extended statistics about the BlobStore.
     */
    @Override
    public Map<Metric, Map<String, Long>> extendedStats() {
        return blobStore.extendedStats();
    }

    @Override
    public boolean isBlobMetadataEnabled() {
        return blobStore.isBlobMetadataEnabled();
    }

    /**
     * Merges index-level and repository-level CryptoMetadata.
     * Priority: Index key greater than Repository key
     * Context: Index context merged with repository context (EncA + EncB)
     *
     * @param indexMetadata The index-level CryptoMetadata
     * @return Merged CryptoMetadata with combined key and context
     */
    private CryptoMetadata mergeCryptoMetadata(CryptoMetadata indexMetadata) {
        // Use index key provider if present, else repository
        String keyProviderName = (indexMetadata.keyProviderName() != null) 
            ? indexMetadata.keyProviderName() 
            : this.repositoryCryptoMetadata.keyProviderName();
            
        String keyProviderType = (indexMetadata.keyProviderType() != null)
            ? indexMetadata.keyProviderType()
            : this.repositoryCryptoMetadata.keyProviderType();
        
        // Merge settings: start with repo, overlay index settings
        org.opensearch.common.settings.Settings.Builder settingsBuilder = 
            org.opensearch.common.settings.Settings.builder()
                .put(this.repositoryCryptoMetadata.settings())
                .put(indexMetadata.settings());
        
        // Merge encryption contexts from settings
        String indexCtx = indexMetadata.settings().get("kms.encryption_context");
        String repoCtx = this.repositoryCryptoMetadata.settings().get("kms.encryption_context");
        
        logger.info("[CSE-CONTEXT-MERGE] Index context (EncA): {}, Repo context (EncB): {}", indexCtx, repoCtx);
        
        if (indexCtx != null && !indexCtx.isEmpty()) {
            // Convert cryptofs format to JSON if needed
            String indexJson = indexCtx.trim().startsWith("{") ? indexCtx : cryptofsToJson(indexCtx);
            logger.info("[CSE-CONTEXT-MERGE] Index context converted to JSON: {}", indexJson);
            
            if (repoCtx != null && !repoCtx.isEmpty()) {
                // Convert repo context to JSON if needed (could be cryptofs format)
                String repoJson = repoCtx.trim().startsWith("{") ? repoCtx : cryptofsToJson(repoCtx);
                logger.info("[CSE-CONTEXT-MERGE] Repo context converted to JSON: {}", repoJson);
                
                // Merge: repo baseline + index overrides
                String mergedJson = mergeJson(indexJson, repoJson);
                logger.info("[CSE-CONTEXT-MERGE] Merged JSON: {}", mergedJson);
                
                // Convert back to cryptofs format for KmsService
                String mergedCryptofs = jsonToCryptofs(mergedJson);
                logger.info("[CSE-CONTEXT-MERGE] Merged context (EncC) in cryptofs format: {}", mergedCryptofs);
                settingsBuilder.put("kms.encryption_context", mergedCryptofs);
            } else {
                logger.info("[CSE-CONTEXT-MERGE] Using index context only (no repo context)");
                settingsBuilder.put("kms.encryption_context", indexCtx);  // Keep original format
            }
        } else if (repoCtx != null && !repoCtx.isEmpty()) {
            logger.info("[CSE-CONTEXT-MERGE] Using repo context only (no index context)");
            settingsBuilder.put("kms.encryption_context", repoCtx);  // Keep original format
        }
        
        logger.info("[CSE-CONTEXT-MERGE] Key provider: name={}, type={}", keyProviderName, keyProviderType);
        
        return new CryptoMetadata(keyProviderName, keyProviderType, settingsBuilder.build());
    }

    /**
     * Converts cryptofs format to JSON.
     * Input: "key1=value1,key2=value2"
     * Output: {"key1":"value1","key2":"value2"}
     */
    private String cryptofsToJson(String cryptofs) {
        StringBuilder sb = new StringBuilder("{");
        for (String pair : cryptofs.split(",")) {
            String[] kv = pair.trim().split("=", 2);
            if (kv.length == 2) {
                if (sb.length() > 1) sb.append(",");
                sb.append('"').append(kv[0].trim()).append("\":\"").append(kv[1].trim()).append('"');
            }
        }
        return sb.append("}").toString();
    }

    /**
     * Converts JSON format back to cryptofs format.
     * Input: {"key1":"value1","key2":"value2"}
     * Output: "key1=value1,key2=value2"
     */
    private String jsonToCryptofs(String json) {
        java.util.Map<String, String> map = new java.util.LinkedHashMap<>();
        parseSimpleJson(json, map);
        
        StringBuilder sb = new StringBuilder();
        boolean first = true;
        for (java.util.Map.Entry<String, String> e : map.entrySet()) {
            if (!first) sb.append(",");
            sb.append(e.getKey()).append("=").append(e.getValue());
            first = false;
        }
        return sb.toString();
    }

    /**
     * Merges two JSON strings (repo + index).
     * Repository context provides baseline, index context overrides.
     */
    private String mergeJson(String indexJson, String repoJson) {
        java.util.Map<String, String> map = new java.util.LinkedHashMap<>();
        
        // Parse repo first (baseline)
        parseSimpleJson(repoJson, map);
        // Parse index second (overrides)
        parseSimpleJson(indexJson, map);
        
        // Build merged JSON
        StringBuilder sb = new StringBuilder("{");
        boolean first = true;
        for (java.util.Map.Entry<String, String> e : map.entrySet()) {
            if (!first) sb.append(",");
            sb.append('"').append(e.getKey()).append("\":\"").append(e.getValue()).append('"');
            first = false;
        }
        return sb.append("}").toString();
    }

    /**
     * Simple JSON parser for string-string maps.
     * Parses JSON format into Map.
     */
    private void parseSimpleJson(String json, java.util.Map<String, String> map) {
        if (json == null || json.isEmpty()) return;
        String s = json.trim();
        if (s.startsWith("{")) s = s.substring(1, s.length() - 1);
        
        int i = 0;
        while (i < s.length()) {
            int ks = s.indexOf('"', i);
            if (ks == -1) break;
            int ke = s.indexOf('"', ks + 1);
            if (ke == -1) break;
            int vs = s.indexOf('"', ke + 1);
            if (vs == -1) break;
            int ve = s.indexOf('"', vs + 1);
            if (ve == -1) break;
            map.put(s.substring(ks + 1, ke), s.substring(vs + 1, ve));
            i = ve + 1;
        }
    }

    /**
     * Closes the EncryptedBlobStore by decrementing the reference count of the CryptoManager and closing the
     * underlying BlobStore. This ensures proper cleanup of resources.
     *
     * @throws IOException If an I/O error occurs while closing the BlobStore.
     */
    @Override
    public void close() throws IOException {
        cryptoHandler.close();
        blobStore.close();
    }

}
