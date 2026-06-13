package com.example.oidcreference.authservice;

import java.time.Duration;
import java.util.Collections;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.script.DefaultRedisScript;
import org.springframework.data.redis.core.script.RedisScript;
import org.springframework.stereotype.Component;

@Component
class RedisStateStore implements StateStore {
  // SADD + PEXPIRE in one server-side round-trip. The rest of the store is
  // meticulous about atomicity (GETDEL, SET XX); doing SADD then EXPIRE as two
  // calls could leave a sub_sessions:{sub} set with no TTL (a leaked index key)
  // if the second hop fails or is reordered. ARGV[2] is the TTL in
  // milliseconds. Returns 1 (unused; the StateStore contract is void).
  private static final RedisScript<Long> ADD_TO_SET_WITH_TTL = new DefaultRedisScript<>(
      "redis.call('SADD', KEYS[1], ARGV[1]); "
          + "redis.call('PEXPIRE', KEYS[1], ARGV[2]); "
          + "return 1",
      Long.class);

  // Atomic sid rotation + breadcrumb: iff KEYS[1] (sess:{old}) exists, write
  // ARGV[1] under KEYS[2] (sess:{new}) PX ARGV[2] ms, write ARGV[3] under KEYS[3]
  // (rotated:{old} breadcrumb) PX ARGV[4] ms, and delete KEYS[1]; else a no-op
  // returning 0. The EXISTS-gate makes rotation inherit SET XX's race-safety: a
  // concurrent logout that DEL'd the old key during the refresh round-trip leaves
  // nothing to rotate, so we fail closed, not resurrect it. The breadcrumb is
  // written in the SAME script as the move (N3) so a concurrent subject-wide
  // logout can never observe sess:{new} without the breadcrumb that lets it
  // follow through — closing the revocation window.
  //
  // Threat-model note (O3): the SET of KEYS[2] is UNCONDITIONAL after the gate —
  // a pre-existing sess:{new} would be clobbered. Safety rests entirely on newSid
  // being a fresh 256-bit CryptoSupport.randomUrlToken, so a collision with a live
  // sid is cryptographically impossible; there is no compare-before-write guard.
  private static final RedisScript<Long> ROTATE_IF_PRESENT = new DefaultRedisScript<>(
      "if redis.call('EXISTS', KEYS[1]) == 1 then "
          + "redis.call('SET', KEYS[2], ARGV[1], 'PX', tonumber(ARGV[2])); "
          + "redis.call('SET', KEYS[3], ARGV[3], 'PX', tonumber(ARGV[4])); "
          + "redis.call('DEL', KEYS[1]); "
          + "return 1 else return 0 end",
      Long.class);

  // Compare-and-set: SET KEYS[1]=ARGV[2] PX ARGV[3] iff GET(KEYS[1]) == ARGV[1].
  // Used to repoint idp_sid:{idpSid} on sid rotation only if a concurrent logout
  // hasn't already cleared/changed it (else the logout would be undone).
  private static final RedisScript<Long> COMPARE_AND_SWAP = new DefaultRedisScript<>(
      "if redis.call('GET', KEYS[1]) == ARGV[1] then "
          + "redis.call('SET', KEYS[1], ARGV[2], 'PX', tonumber(ARGV[3])); "
          + "return 1 else return 0 end",
      Long.class);

  // Release a lease only if we still own it (value matches), so an instance
  // never deletes a lock another acquired after ours expired by TTL.
  private static final RedisScript<Long> COMPARE_AND_DELETE = new DefaultRedisScript<>(
      "if redis.call('GET', KEYS[1]) == ARGV[1] then "
          + "redis.call('DEL', KEYS[1]); "
          + "return 1 else return 0 end",
      Long.class);

  private final StringRedisTemplate redis;

  RedisStateStore(StringRedisTemplate redis) {
    this.redis = redis;
  }

  @Override
  public void put(String key, String value, Duration ttl) {
    redis.opsForValue().set(key, value, ttl);
  }

  @Override
  public boolean putIfAbsent(String key, String value, Duration ttl) {
    Boolean stored = redis.opsForValue().setIfAbsent(key, value, ttl);
    return Boolean.TRUE.equals(stored);
  }

  @Override
  public boolean putIfPresent(String key, String value, Duration ttl) {
    Boolean stored = redis.opsForValue().setIfPresent(key, value, ttl);
    return Boolean.TRUE.equals(stored);
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
    Long rotated = redis.execute(
        ROTATE_IF_PRESENT,
        List.of(oldKey, newKey, breadcrumbKey),
        value,
        Long.toString(ttl.toMillis()),
        breadcrumbValue,
        Long.toString(breadcrumbTtl.toMillis()));
    return rotated != null && rotated == 1L;
  }

  @Override
  public boolean compareAndSwap(String key, String expected, String newValue, Duration ttl) {
    Long swapped = redis.execute(
        COMPARE_AND_SWAP,
        List.of(key),
        expected,
        newValue,
        Long.toString(ttl.toMillis()));
    return swapped != null && swapped == 1L;
  }

  @Override
  public boolean compareAndDelete(String key, String expected) {
    Long deleted = redis.execute(COMPARE_AND_DELETE, List.of(key), expected);
    return deleted != null && deleted == 1L;
  }

  @Override
  public Optional<String> get(String key) {
    return Optional.ofNullable(redis.opsForValue().get(key));
  }

  @Override
  public Optional<String> getAndDelete(String key) {
    return Optional.ofNullable(redis.opsForValue().getAndDelete(key));
  }

  @Override
  public void delete(String key) {
    redis.delete(key);
  }

  @Override
  public Duration ttl(String key) {
    Long seconds = redis.getExpire(key);
    if (seconds == null || seconds <= 0) {
      return Duration.ZERO;
    }
    return Duration.ofSeconds(seconds);
  }

  @Override
  public void expire(String key, Duration ttl) {
    redis.expire(key, ttl);
  }

  @Override
  public void addToSet(String key, String member, Duration ttl) {
    redis.execute(
        ADD_TO_SET_WITH_TTL,
        List.of(key),
        member,
        Long.toString(ttl.toMillis()));
  }

  @Override
  public void removeFromSet(String key, String member) {
    redis.opsForSet().remove(key, member);
  }

  @Override
  public Set<String> members(String key) {
    Set<String> members = redis.opsForSet().members(key);
    return members == null ? Collections.emptySet() : members;
  }
}
