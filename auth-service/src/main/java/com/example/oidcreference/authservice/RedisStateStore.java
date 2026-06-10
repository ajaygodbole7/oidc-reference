package com.example.oidcreference.authservice;

import java.time.Duration;
import java.util.Collections;
import java.util.Optional;
import java.util.Set;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Component;

@Component
class RedisStateStore implements StateStore {
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
    redis.opsForSet().add(key, member);
    redis.expire(key, ttl);
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
