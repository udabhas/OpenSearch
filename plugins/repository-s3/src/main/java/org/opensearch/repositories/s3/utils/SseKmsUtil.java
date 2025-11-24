/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.repositories.s3.utils;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.common.Nullable;
import software.amazon.awssdk.services.s3.model.CreateMultipartUploadRequest;
import software.amazon.awssdk.services.s3.model.PutObjectRequest;
import software.amazon.awssdk.services.s3.model.ServerSideEncryption;

import org.opensearch.repositories.s3.S3BlobStore;
import org.opensearch.repositories.s3.async.UploadRequest;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

public class SseKmsUtil {
    private static final Logger logger = LogManager.getLogger(SseKmsUtil.class);

    /**
     * Merges index-level and repository-level encryption contexts, converts to JSON format if needed,
     * and Base64 encodes for S3.
     *
     * Merging strategy: Repository context provides baseline, index context keys override on conflict.
     * This ensures KMS grants created with combined context (EncA + EncB) work correctly.
     *
     * @param indexEncContext Index-level encryption context (EncA) - can be cryptofs or JSON format
     * @param repoEncContext Repository-level encryption context (EncB) - already Base64 encoded JSON
     * @return Base64 encoded merged JSON encryption context, or null if both are null
     */
    public static String mergeAndEncodeEncryptionContexts(
        @Nullable String indexEncContext,
        @Nullable String repoEncContext
    ) {
        // If both null, return null
        if ((indexEncContext == null || indexEncContext.isEmpty()) && 
            (repoEncContext == null || repoEncContext.isEmpty())) {
            return null;
        }
        
        // Parse index context to JSON (handling cryptofs format)
        String indexJson = null;
        if (indexEncContext != null && !indexEncContext.isEmpty()) {
            String trimmed = indexEncContext.trim();
            if (trimmed.startsWith("{")) {
                // Already JSON
                indexJson = trimmed;
            } else {
                // Convert from cryptofs format
                indexJson = convertCryptofsToJson(trimmed);
            }
        }
        
        // Decode repository context from Base64 (already JSON)
        String repoJson = null;
        if (repoEncContext != null && !repoEncContext.isEmpty()) {
            try {
                byte[] decoded = Base64.getDecoder().decode(repoEncContext);
                repoJson = new String(decoded, StandardCharsets.UTF_8);
            } catch (IllegalArgumentException e) {
                logger.warn("Failed to decode repository encryption context, using as-is", e);
                repoJson = repoEncContext;
            }
        }
        
        // Merge contexts
        String mergedJson = mergeJsonContexts(indexJson, repoJson);
        
        logger.info("[ENC-MERGE] Index={}, Repo={}, Merged={}", 
                   indexJson, repoJson, mergedJson);
        
        // Base64 encode the merged result
        String encoded = Base64.getEncoder().encodeToString(mergedJson.getBytes(StandardCharsets.UTF_8));
        logger.info("[ENC-MERGE] Final Base64={}", encoded);
        
        return encoded;
    }
    
    /**
     * Converts cryptofs format (key=value,key2=value2) to JSON format {"key":"value","key2":"value2"}
     */
    private static String convertCryptofsToJson(String cryptofsFormat) {
        StringBuilder jsonBuilder = new StringBuilder("{");
        String[] pairs = cryptofsFormat.split(",");
        boolean first = true;
        
        for (String pair : pairs) {
            String[] keyValue = pair.trim().split("=", 2);
            if (keyValue.length == 2) {
                if (!first) {
                    jsonBuilder.append(",");
                }
                String key = keyValue[0].trim().replace("\"", "\\\"");
                String value = keyValue[1].trim().replace("\"", "\\\"");
                jsonBuilder.append("\"").append(key).append("\":\"").append(value).append("\"");
                first = false;
            }
        }
        jsonBuilder.append("}");
        
        return jsonBuilder.toString();
    }
    
    /**
     * Merges two JSON encryption contexts.
     * Strategy: Start with repo context, add/override with index context keys.
     * 
     * @param indexJson Index-level context in JSON format
     * @param repoJson Repository-level context in JSON format
     * @return Merged JSON string
     */
    private static String mergeJsonContexts(@Nullable String indexJson, @Nullable String repoJson) {
        // If only one is present, return it
        if (indexJson == null || indexJson.isEmpty()) {
            return repoJson != null ? repoJson : "{}";
        }
        if (repoJson == null || repoJson.isEmpty()) {
            return indexJson;
        }
        
        // Parse both JSON strings into key-value pairs (simple parsing)
        java.util.Map<String, String> merged = new java.util.LinkedHashMap<>();
        
        // Add repository context first (baseline)
        parseJsonToMap(repoJson, merged);
        
        // Add/override with index context
        parseJsonToMap(indexJson, merged);
        
        // Convert back to JSON
        StringBuilder result = new StringBuilder("{");
        boolean first = true;
        for (java.util.Map.Entry<String, String> entry : merged.entrySet()) {
            if (!first) {
                result.append(",");
            }
            result.append("\"").append(entry.getKey()).append("\":\"").append(entry.getValue()).append("\"");
            first = false;
        }
        result.append("}");
        
        return result.toString();
    }
    
    /**
     * Simple JSON parser for string-to-string maps.
     * Extracts key-value pairs from JSON like {"key1":"value1","key2":"value2"}
     */
    private static void parseJsonToMap(String json, java.util.Map<String, String> map) {
        if (json == null || json.isEmpty()) {
            return;
        }
        
        // Remove outer braces
        String content = json.trim();
        if (content.startsWith("{") && content.endsWith("}")) {
            content = content.substring(1, content.length() - 1);
        }
        
        // Simple parsing (assumes no nested objects, escaped quotes handled)
        int pos = 0;
        while (pos < content.length()) {
            // Find key
            int keyStart = content.indexOf("\"", pos);
            if (keyStart == -1) break;
            int keyEnd = content.indexOf("\"", keyStart + 1);
            if (keyEnd == -1) break;
            String key = content.substring(keyStart + 1, keyEnd);
            
            // Find value
            int valueStart = content.indexOf("\"", keyEnd + 1);
            if (valueStart == -1) break;
            int valueEnd = content.indexOf("\"", valueStart + 1);
            if (valueEnd == -1) break;
            String value = content.substring(valueStart + 1, valueEnd);
            
            map.put(key, value);
            pos = valueEnd + 1;
        }
    }

    // CreateMultipartUploadRequest with S3BlobStore (with index override)
    public static void configureEncryptionSettings(
        CreateMultipartUploadRequest.Builder builder,
        S3BlobStore blobStore,
        @Nullable String indexKmsKey,
        @Nullable String indexEncContext
    ) {
        if (blobStore.serverSideEncryptionType().equals(ServerSideEncryption.AES256.toString())) {
            builder.serverSideEncryption(ServerSideEncryption.AES256);
        } else if (blobStore.serverSideEncryptionType().equals(ServerSideEncryption.AWS_KMS.toString())) {
            // Priority: index key → repo key
            String kmsKey = (indexKmsKey != null) ? indexKmsKey : blobStore.serverSideEncryptionKmsKey();

            // MERGE encryption contexts: EncA (index) + EncB (repository)
            // This ensures KMS grants work correctly with combined context
            String encContext = mergeAndEncodeEncryptionContexts(
                indexEncContext,
                blobStore.serverSideEncryptionEncryptionContext()
            );

            builder.serverSideEncryption(ServerSideEncryption.AWS_KMS);
            builder.ssekmsKeyId(kmsKey);
            builder.bucketKeyEnabled(blobStore.serverSideEncryptionBucketKey());
            builder.ssekmsEncryptionContext(encContext);
        }
    }

    // PutObjectRequest with S3BlobStore (with index override)
    public static void configureEncryptionSettings(
        PutObjectRequest.Builder builder,
        S3BlobStore blobStore,
        @Nullable String indexKmsKey,
        @Nullable String indexEncContext
    ) {
        if (blobStore.serverSideEncryptionType().equals(ServerSideEncryption.AES256.toString())) {
            builder.serverSideEncryption(ServerSideEncryption.AES256);
        } else if (blobStore.serverSideEncryptionType().equals(ServerSideEncryption.AWS_KMS.toString())) {
            // Priority: index key → repo key
            String kmsKey = (indexKmsKey != null) ? indexKmsKey : blobStore.serverSideEncryptionKmsKey();

            // MERGE encryption contexts: EncA (index) + EncB (repository)
            // This ensures KMS grants work correctly with combined context
            String encContext = mergeAndEncodeEncryptionContexts(
                indexEncContext,
                blobStore.serverSideEncryptionEncryptionContext()
            );

            builder.serverSideEncryption(ServerSideEncryption.AWS_KMS);
            builder.ssekmsKeyId(kmsKey);
            builder.bucketKeyEnabled(blobStore.serverSideEncryptionBucketKey());
            builder.ssekmsEncryptionContext(encContext);
        }
    }

    // PutObjectRequest with S3BlobStore (repository-level only)
    public static void configureEncryptionSettings(PutObjectRequest.Builder builder, S3BlobStore blobStore) {
        // Delegate to overload with null index settings
        configureEncryptionSettings(builder, blobStore, null, null);
    }

    public static void configureEncryptionSettings(CreateMultipartUploadRequest.Builder builder, UploadRequest uploadRequest) {
        if (uploadRequest.getServerSideEncryptionType().equals(ServerSideEncryption.AES256.toString())) {
            builder.serverSideEncryption(ServerSideEncryption.AES256);
        } else if (uploadRequest.getServerSideEncryptionType().equals(ServerSideEncryption.AWS_KMS.toString())) {
            builder.serverSideEncryption(ServerSideEncryption.AWS_KMS);
            builder.ssekmsKeyId(uploadRequest.getServerSideEncryptionKmsKey());
            builder.bucketKeyEnabled(uploadRequest.getServerSideEncryptionBucketKey());
            builder.ssekmsEncryptionContext(uploadRequest.getServerSideEncryptionEncryptionContext());
        }
    }

    public static void configureEncryptionSettings(PutObjectRequest.Builder builder, UploadRequest uploadRequest) {
        if (uploadRequest.getServerSideEncryptionType().equals(ServerSideEncryption.AES256.toString())) {
            builder.serverSideEncryption(ServerSideEncryption.AES256);
        } else if (uploadRequest.getServerSideEncryptionType().equals(ServerSideEncryption.AWS_KMS.toString())) {
            builder.serverSideEncryption(ServerSideEncryption.AWS_KMS);
            builder.ssekmsKeyId(uploadRequest.getServerSideEncryptionKmsKey());
            builder.bucketKeyEnabled(uploadRequest.getServerSideEncryptionBucketKey());
            builder.ssekmsEncryptionContext(uploadRequest.getServerSideEncryptionEncryptionContext());
        }
    }
}
