package com.example.oidcreference.authservice;

import java.util.function.Supplier;

/**
 * Serializes the refresh-token grant for a single session so two concurrent
 * {@code POST /internal/resolve} calls on the same {@code sid} collapse to ONE
 * upstream refresh: the loser, on acquiring the lock, re-reads {@code sess:{sid}}
 * and finds the already-rotated token (SPEC-0001 §7.2).
 *
 * <p>The default {@link InProcessRefreshLock} is a per-JVM lock — correct for
 * the single-instance reference. This interface exists so the lock is a swap,
 * not a rewrite, mirroring the {@link StateStore} / {@link RedisStateStore}
 * split: a horizontally-scaled deployment provides a distributed implementation
 * backed by the session store — {@code SET refresh_lock:{sid} <token> NX PX
 * <ttl>} to acquire, a compare-and-delete (Lua, check the token matches before
 * {@code DEL}) to release, and the same loser-re-reads-{@code sess:{sid}}
 * behaviour on contention. The phantom-token shape puts {@code /internal/resolve}
 * on every {@code /api} request, so this is the more pressing of the two
 * scale-out blockers. See {@code docs/operations/production-hardening.md} and
 * {@code docs/architecture/phantom-token-session-resolution.md}.
 */
interface RefreshLock {

  /**
   * Run {@code action} while holding the lock for {@code key}, then release it.
   * The lock is released even if {@code action} throws (the throwable
   * propagates to the caller).
   *
   * @param key the lock key — the session {@code sid}
   * @param action the work to run under mutual exclusion for {@code key}
   * @return whatever {@code action} returns
   */
  <T> T withLock(String key, Supplier<T> action);
}
