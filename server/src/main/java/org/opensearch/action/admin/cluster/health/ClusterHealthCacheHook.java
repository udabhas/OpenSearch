/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.action.admin.cluster.health;

/**
 * Hook for plugins to register cache cleanup callbacks triggered during cluster health checks.
 * Used for benchmarking to simulate cold cache conditions between iterations.
 *
 * @opensearch.internal
 */
public class ClusterHealthCacheHook {
    private static volatile Runnable cacheCleanup;

    public static void setCacheCleanup(Runnable cleanup) {
        cacheCleanup = cleanup;
    }

    public static void runCacheCleanup() {
        if (cacheCleanup != null) cacheCleanup.run();
    }
}
