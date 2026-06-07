package com.example.oidcreference.authservice;

import java.time.Duration;
import java.util.Optional;

interface StateStore {
  void put(String key, String value, Duration ttl);

  Optional<String> get(String key);

  Optional<String> getAndDelete(String key);

  void delete(String key);

  // Refresh the TTL on an existing key without rewriting its value. Sliding
  // session expiration uses this so a concurrent token refresh cannot be
  // clobbered by a stale read-then-rewrite.
  void expire(String key, Duration ttl);
}
