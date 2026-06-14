package com.example.oidcreference.authservice;

import java.time.Duration;
import java.util.function.Supplier;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Cross-instance {@link RefreshLock} built on the vendor-neutral
 * {@link StateStore} abstraction — it knows nothing about Valkey/Redis, the
 * local Compose stack, ports, or dev secrets; it speaks only {@code putIfAbsent}
 * ({@code SET key token NX PX ttl}) to acquire and {@code compareAndDelete}
 * ({@code GET==token then DEL}) to release. Swap the {@link StateStore} impl and
 * this lock follows.
 *
 * <p>Algorithm (mirrors the recipe in {@code production-hardening.md}):
 * <ol>
 *   <li><b>Acquire</b> {@code refresh_lock:{key}} with a unique token and a TTL.
 *       The TTL bounds a crashed holder — the lease self-expires so the lock
 *       cannot wedge.</li>
 *   <li><b>Contend</b>: a caller that cannot acquire polls until it can, up to
 *       {@code maxWait}. Set {@code maxWait} above the lease TTL so a dead
 *       holder's lease always lapses within the wait; the loser then acquires
 *       and runs {@code action}, which re-reads {@code sess:{sid}} and finds the
 *       winner's already-rotated token (the {@link RefreshLock} contract) — so
 *       the two callers collapse to ONE upstream refresh.</li>
 *   <li><b>Release</b> with compare-and-delete so an instance never deletes a
 *       lease another instance acquired after ours expired by TTL.</li>
 *   <li><b>Fail closed</b>: if the lease cannot be acquired within {@code
 *       maxWait}, throw rather than run {@code action} unguarded — running it
 *       without the lock would risk the double-refresh / reuse-detection logout
 *       this lock exists to prevent. The controller maps the throw to a
 *       transient 5xx; the gateway keeps the session cookie and retries.</li>
 * </ol>
 *
 * <p>Not wired by default — {@link InProcessRefreshLock} is correct for the
 * single-instance reference. Selected via {@code app.refresh-lock=distributed}
 * for a horizontally-scaled deployment.
 */
class DistributedRefreshKeyLock implements RefreshLock {
  private static final Logger log = LoggerFactory.getLogger(DistributedRefreshKeyLock.class);
  private static final String LOCK_PREFIX = "refresh_lock:";

  private final StateStore store;
  private final Duration ttl;
  private final Duration maxWait;
  private final Duration poll;

  DistributedRefreshKeyLock(StateStore store, Duration ttl, Duration maxWait, Duration poll) {
    this.store = store;
    this.ttl = ttl;
    this.maxWait = maxWait;
    this.poll = poll;
  }

  @Override
  public <T> T withLock(String key, Supplier<T> action) {
    String lockKey = LOCK_PREFIX + key;
    String token = CryptoSupport.randomUrlToken(16);
    acquire(lockKey, token, System.nanoTime() + maxWait.toNanos());
    try {
      return action.get();
    } finally {
      store.compareAndDelete(lockKey, token);
    }
  }

  // Acquire the lease, or throw RefreshLockUnavailableException so the caller
  // fails closed — never run the refresh unguarded (double-spend the refresh
  // token -> reuse detection -> user logged out). A store error WHILE ACQUIRING
  // is also a transient lock-acquire failure, deliberately distinct from a
  // failure in the refresh action itself (which the controller maps separately,
  // so an action error is never mislabeled "lock unavailable").
  private void acquire(String lockKey, String token, long deadlineNanos) {
    while (true) {
      boolean acquired;
      try {
        acquired = store.putIfAbsent(lockKey, token, ttl);
      } catch (RuntimeException e) {
        throw new RefreshLockUnavailableException("refresh lock acquire failed (store error)", e);
      }
      if (acquired) {
        return;
      }
      if (System.nanoTime() >= deadlineNanos) {
        log.warn("refresh lock not acquired within {} for a session; failing closed", maxWait);
        throw new RefreshLockUnavailableException("could not acquire refresh lock within " + maxWait);
      }
      sleep(poll);
    }
  }

  private static void sleep(Duration d) {
    try {
      Thread.sleep(Math.max(1L, d.toMillis()));
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
      // An interrupt mid-wait must not silently fall through to an unguarded
      // refresh — fail closed.
      throw new RefreshLockUnavailableException("interrupted waiting for refresh lock", e);
    }
  }
}
