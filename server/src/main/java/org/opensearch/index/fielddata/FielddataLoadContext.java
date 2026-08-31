/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.index.fielddata;

/**
 * Per-thread marker recording that a field data build is in progress, so a {@code Directory} can tell the
 * build apart from the query phase that follows it (both derive the same region of the same input, so no
 * argument-based predicate can separate them).
 *
 * <p>Set by {@code IndicesFieldDataCache} around {@code loadDirect} and cleared in a {@code finally},
 * because search threads are pooled and a leaked marker would affect the next request. A depth counter
 * rather than a boolean so a nested load cannot clear an outer build's marker. Not set around
 * {@code loadGlobalDirect}, which builds an OrdinalMap from already-cached leaves and reads nothing.
 *
 * @opensearch.internal
 */
public final class FielddataLoadContext {

    private static final ThreadLocal<int[]> DEPTH = new ThreadLocal<>();

    private FielddataLoadContext() {}

    /** Pair with {@link #clearFielddataLoad()} in a finally. */
    public static void markFielddataLoad() {
        int[] depth = DEPTH.get();
        if (depth == null) {
            depth = new int[1];
            DEPTH.set(depth);
        }
        depth[0]++;
    }

    /** Ends one nesting level, removing the marker at depth zero. */
    public static void clearFielddataLoad() {
        final int[] depth = DEPTH.get();
        if (depth != null && --depth[0] <= 0) {
            DEPTH.remove();
        }
    }

    /** True while a field data build runs on this thread. A ThreadLocal lookup plus a null check. */
    public static boolean isFielddataLoad() {
        final int[] depth = DEPTH.get();
        return depth != null && depth[0] > 0;
    }
}
