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
  private final Map<String, Set<String>> sets = new ConcurrentHashMap<>();
  private final Map<String, Duration> ttls = new ConcurrentHashMap<>();
  private final AtomicInteger putCallsWithZeroTtl = new AtomicInteger();
  private final AtomicInteger expireCalls = new AtomicInteger();

  @Override
  public void put(String key, String value, Duration ttl) {
    if (ttl == null || ttl.isZero() || ttl.isNegative()) {
      putCallsWithZeroTtl.incrementAndGet();
    }
    values.put(key, value);
    ttls.put(key, ttl == null ? Duration.ZERO : ttl);
  }

  @Override
  public boolean putIfAbsent(String key, String value, Duration ttl) {
    String existing = values.putIfAbsent(key, value);
    if (existing == null) {
      ttls.put(key, ttl == null ? Duration.ZERO : ttl);
      return true;
    }
    return false;
  }

  @Override
  public boolean putIfPresent(String key, String value, Duration ttl) {
    // Mirror Redis SET ... XX: write (and reset TTL) only if the key exists.
    return values.computeIfPresent(key, (k, existing) -> {
      ttls.put(k, ttl == null ? Duration.ZERO : ttl);
      return value;
    }) != null;
  }

  @Override
  public boolean rotateIfPresent(
      String oldKey,
      String newKey,
      String value,
      Duration ttl,
      String breadcrumbKey,
      String breadcrumbValue,
      Duration breadcrumbTtl) {
    // Mirror the Redis EXISTS-gated rotate: write newKey + breadcrumb + drop
    // oldKey only if oldKey existed (else write NOTHING). values.remove is atomic;
    // the test double does not need true cross-key atomicity.
    String existing = values.remove(oldKey);
    if (existing == null) {
      return false;
    }
    ttls.remove(oldKey);
    values.put(newKey, value);
    ttls.put(newKey, ttl == null ? Duration.ZERO : ttl);
    values.put(breadcrumbKey, breadcrumbValue);
    ttls.put(breadcrumbKey, breadcrumbTtl == null ? Duration.ZERO : breadcrumbTtl);
    return true;
  }

  @Override
  public boolean compareAndSwap(String key, String expected, String newValue, Duration ttl) {
    // Atomic per key via compute: set only if the current value equals expected.
    boolean[] swapped = {false};
    values.compute(key, (k, current) -> {
      if (expected.equals(current)) {
        swapped[0] = true;
        ttls.put(k, ttl == null ? Duration.ZERO : ttl);
        return newValue;
      }
      return current;
    });
    return swapped[0];
  }

  @Override
  public boolean compareAndDelete(String key, String expected) {
    // Atomic per key via compute: returning null removes the mapping.
    boolean[] deleted = {false};
    values.compute(key, (k, current) -> {
      if (expected.equals(current)) {
        deleted[0] = true;
        ttls.remove(k);
        return null;
      }
      return current;
    });
    return deleted[0];
  }

  @Override
  public Optional<String> get(String key) {
    return Optional.ofNullable(values.get(key));
  }

  @Override
  public Optional<String> getAndDelete(String key) {
    ttls.remove(key);
    return Optional.ofNullable(values.remove(key));
  }

  @Override
  public void delete(String key) {
    values.remove(key);
    sets.remove(key);
    ttls.remove(key);
  }

  @Override
  public void addToSet(String key, String member, Duration ttl) {
    // ConcurrentHashMap.compute is atomic per key — mirrors Redis SADD being
    // atomic per member, so concurrent adds for the same subject cannot lose
    // a member to a read-modify-write race.
    sets.compute(key, (k, existing) -> {
      Set<String> set = existing == null ? ConcurrentHashMap.newKeySet() : existing;
      set.add(member);
      return set;
    });
    // Extend-only TTL (mirrors the Redis SADD+PTTL-compare): a later short-lived
    // session must not shrink the shared index key below a still-live longer one.
    Duration next = ttl == null ? Duration.ZERO : ttl;
    ttls.merge(key, next, (cur, n) -> n.compareTo(cur) > 0 ? n : cur);
  }

  @Override
  public void removeFromSet(String key, String member) {
    sets.computeIfPresent(key, (k, set) -> {
      set.remove(member);
      return set.isEmpty() ? null : set;
    });
    if (!sets.containsKey(key)) {
      ttls.remove(key);
    }
  }

  @Override
  public boolean swapMemberIfPresent(String key, String oldMember, String newMember, Duration ttl) {
    // Atomic per key via compute (mirrors the Redis SISMEMBER-gated SREM+SADD):
    // swap only if oldMember is currently in the set; else no-op false.
    boolean[] swapped = {false};
    sets.computeIfPresent(key, (k, set) -> {
      if (set.contains(oldMember)) {
        set.remove(oldMember);
        set.add(newMember);
        swapped[0] = true;
        // Extend-only TTL (mirrors the Redis PTTL-compare): rotating a short-lived
        // sid must not shrink the shared idp_sid set below a still-live longer sid.
        Duration next = ttl == null ? Duration.ZERO : ttl;
        ttls.merge(k, next, (cur, n) -> n.compareTo(cur) > 0 ? n : cur);
      }
      return set.isEmpty() ? null : set;
    });
    return swapped[0];
  }

  @Override
  public Set<String> members(String key) {
    Set<String> set = sets.get(key);
    return set == null ? Collections.emptySet() : Set.copyOf(set);
  }

  @Override
  public Duration ttl(String key) {
    return ttls.getOrDefault(key, Duration.ZERO);
  }

  @Override
  public void expire(String key, Duration ttl) {
    expireCalls.incrementAndGet();
    if (values.containsKey(key)) {
      ttls.put(key, ttl == null ? Duration.ZERO : ttl);
    }
  }

  int putCallsWithZeroTtl() {
    return putCallsWithZeroTtl.get();
  }

  int expireCalls() {
    return expireCalls.get();
  }

  Set<String> keys() {
    Set<String> all = new java.util.HashSet<>(values.keySet());
    all.addAll(sets.keySet());
    return Collections.unmodifiableSet(all);
  }

  void clear() {
    values.clear();
    sets.clear();
    ttls.clear();
    putCallsWithZeroTtl.set(0);
    expireCalls.set(0);
  }
}
