package com.example.oidcreference.authservice;

import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.locks.ReentrantLock;
import java.util.function.Supplier;

/**
 * Per-JVM {@link RefreshLock}: a reference-counted {@link ReentrantLock} per
 * key, held in a {@link ConcurrentHashMap}. The entry is created on first
 * acquire and removed once the last holder releases, so the map cannot grow
 * without bound across many distinct sids.
 *
 * <p>SINGLE-INSTANCE ONLY. With two or more Auth Service instances, each has its
 * own map, so two instances can refresh the same session concurrently — both
 * send the same refresh token to the IdP and, under rotation + reuse detection,
 * the second is rejected as {@code invalid_grant} and the session invalidated
 * (naive horizontal scaling logs active users out). That is the documented
 * scale-out boundary, not a bug; see {@link RefreshLock} for the distributed
 * swap.
 *
 * <p>Provided as a bean by {@link RefreshLockConfig} (the default), not via a
 * stereotype, so the lock implementation is selectable by configuration.
 */
class InProcessRefreshLock implements RefreshLock {
  private final ConcurrentHashMap<String, LockRef> locks = new ConcurrentHashMap<>();

  @Override
  public <T> T withLock(String key, Supplier<T> action) {
    LockRef ref = acquire(key);
    ref.lock.lock();
    try {
      return action.get();
    } finally {
      ref.lock.unlock();
      release(key, ref);
    }
  }

  private LockRef acquire(String key) {
    return locks.compute(key, (ignored, existing) -> {
      if (existing == null) {
        return new LockRef();
      }
      existing.refs.incrementAndGet();
      return existing;
    });
  }

  private void release(String key, LockRef ref) {
    locks.computeIfPresent(key, (ignored, existing) -> {
      if (existing != ref) {
        return existing;
      }
      return existing.refs.decrementAndGet() == 0 ? null : existing;
    });
  }

  /**
   * Visible for testing: number of keys currently holding a lock entry. Must
   * return to 0 once every holder has released (the reference-count cleanup
   * that bounds map growth).
   */
  int trackedKeys() {
    return locks.size();
  }

  private static final class LockRef {
    private final ReentrantLock lock = new ReentrantLock();
    private final AtomicInteger refs = new AtomicInteger(1);
  }
}
