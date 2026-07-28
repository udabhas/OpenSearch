/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */
package org.opensearch.search.profile;

/**
 * Thread-scoped holder that exposes the current leaf's {@link AbstractProfileBreakdown} to
 * profiling-aware components (e.g. storage plugins) while a single leaf is being scored.
 *
 * <p>{@link org.opensearch.search.internal.ContextIndexSearcher#searchLeaf} sets this around the
 * per-leaf scoring region (on the slice/search thread) and clears it in a finally block. Deep code
 * that wants to record per-query profiling can read {@link #get()} (null when not profiling) and pull
 * its own registered {@link ProfileMetric} out by name via {@link AbstractProfileBreakdown#getMetric}.
 *
 * <p>Core stays plugin-agnostic: it only sets the breakdown; it has no knowledge of which metrics a
 * plugin registered.
 *
 * @opensearch.internal
 */
public final class ProfileBreakdownHolder {

    private static final ThreadLocal<AbstractProfileBreakdown> CURRENT = new ThreadLocal<>();

    private ProfileBreakdownHolder() {}

    /** Sets the current leaf breakdown for this thread. */
    public static void set(AbstractProfileBreakdown breakdown) {
        CURRENT.set(breakdown);
    }

    /** @return the current leaf breakdown, or {@code null} when not profiling. */
    public static AbstractProfileBreakdown get() {
        return CURRENT.get();
    }

    /** Clears the current leaf breakdown for this thread. */
    public static void clear() {
        CURRENT.remove();
    }
}
