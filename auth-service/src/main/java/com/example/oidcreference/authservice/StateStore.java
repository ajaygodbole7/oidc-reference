package com.example.oidcreference.authservice;

import java.time.Duration;
import java.util.Optional;
import java.util.Set;

interface StateStore {
  void put(String key, String value, Duration ttl);

  boolean putIfAbsent(String key, String value, Duration ttl);

  // Atomic write-only-if-the-key-already-exists (Redis SET ... XX). Returns
  // false (a no-op) when the key is absent. The refresh path uses this so a
  // session deleted by a concurrent logout between the read and the write is
  // NOT resurrected — the delete paths do not share the per-sid refresh lock.
  boolean putIfPresent(String key, String value, Duration ttl);

  // Atomic rotate: iff oldKey exists, write value under newKey (with ttl) and
  // delete oldKey, returning true. If oldKey is absent — e.g. a concurrent
  // logout deleted sess:{sid} during a refresh round-trip — this is a no-op
  // returning false: the session is NOT resurrected under newKey. The sid
  // rotation on refresh uses this so it inherits putIfPresent's race-safety.
  boolean rotateIfPresent(String oldKey, String newKey, String value, Duration ttl);

  // Atomic compare-and-set: set key=newValue (with ttl) iff key currently equals
  // expected. Returns false (no-op) when the key is absent or holds a different
  // value. The sid-rotation index rekey uses this on idp_sid:{idpSid} so a
  // concurrent back-channel logout that cleared the index is not clobbered by the
  // rotation re-pointing it — if the CAS fails, the rotation aborts (fail closed).
  boolean compareAndSwap(String key, String expected, String newValue, Duration ttl);

  Optional<String> get(String key);

  Optional<String> getAndDelete(String key);

  void delete(String key);

  Duration ttl(String key);

  // Refresh the TTL on an existing key without rewriting its value. Sliding
  // session expiration uses this so a concurrent token refresh cannot be
  // clobbered by a stale read-then-rewrite.
  void expire(String key, Duration ttl);

  // --- Set-typed keys (Redis SADD/SREM/SMEMBERS) ---------------------------
  // The subject→sessions index (sub_sessions:{sub}) is a SET, not a
  // newline-encoded string. Native set ops are atomic per member, so two
  // concurrent logins for the same subject can no longer lose a sid to a
  // read-decode-modify-write race. Each add also (re)sets the key's TTL.
  void addToSet(String key, String member, Duration ttl);

  void removeFromSet(String key, String member);

  Set<String> members(String key);
}
