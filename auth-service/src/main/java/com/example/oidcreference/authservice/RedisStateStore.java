package com.example.oidcreference.authservice;

import java.time.Duration;
import java.util.Optional;
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
  public void expire(String key, Duration ttl) {
    redis.expire(key, ttl);
  }
}
