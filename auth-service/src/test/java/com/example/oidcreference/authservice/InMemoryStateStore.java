package com.example.oidcreference.authservice;

import java.time.Duration;
import java.util.Collections;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Shared in-memory {@link StateStore} for tests. Pulled out of the
 * per-test-class duplicates so behavior changes (e.g. tracking
 * {@code put(..., Duration.ZERO)} for the B3 defensive guard) land in one
 * file. The class is package-private so only tests in this package can
 * instantiate it.
 *
 * <p>Two pieces of observable extra state beyond the StateStore contract:
 *
 * <ul>
 *   <li>{@link #keys()} — read-only set of the keys currently stored, so
 *       tests can assert presence/absence patterns ({@code "tx:"}, {@code "sess:"}).
 *   <li>{@link #putCallsWithZeroTtl()} — counter incremented every time
 *       {@code put} is called with a null / zero / negative TTL. Used by
 *       the B3 guard tests to prove the controller deletes rather than
 *       passing a bogus TTL to the backend.
 * </ul>
 */
class InMemoryStateStore implements StateStore {
  private final Map<String, String> values = new ConcurrentHashMap<>();
  private final AtomicInteger putCallsWithZeroTtl = new AtomicInteger();

  @Override
  public void put(String key, String value, Duration ttl) {
    if (ttl == null || ttl.isZero() || ttl.isNegative()) {
      putCallsWithZeroTtl.incrementAndGet();
    }
    values.put(key, value);
  }

  @Override
  public Optional<String> get(String key) {
    return Optional.ofNullable(values.get(key));
  }

  @Override
  public Optional<String> getAndDelete(String key) {
    return Optional.ofNullable(values.remove(key));
  }

  @Override
  public void delete(String key) {
    values.remove(key);
  }

  @Override
  public void expire(String key, Duration ttl) {
    // no-op for in-memory; sliding-TTL behavior isn't exercised here
  }

  int putCallsWithZeroTtl() {
    return putCallsWithZeroTtl.get();
  }

  Set<String> keys() {
    return Collections.unmodifiableSet(values.keySet());
  }

  void clear() {
    values.clear();
    putCallsWithZeroTtl.set(0);
  }
}
