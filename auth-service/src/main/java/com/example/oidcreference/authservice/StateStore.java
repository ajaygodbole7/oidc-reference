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

  // Atomic rotate + breadcrumb: iff oldKey exists, write value under newKey (ttl),
  // write breadcrumbValue under breadcrumbKey (breadcrumbTtl), and delete oldKey —
  // all atomically — returning true. If oldKey is absent (e.g. a concurrent logout
  // deleted sess:{sid} during a refresh round-trip) this is a no-op returning
  // false: nothing is written, so the session is NOT resurrected and NO orphan
  // breadcrumb is left.
  //
  // Folding the breadcrumb INTO the move is load-bearing for revocation safety
  // (N3): the sid rotation on refresh leaves a rotated:{old}->new breadcrumb so a
  // logout that reaches the OLD sid can follow it to the live new session. If the
  // breadcrumb were a SEPARATE write after the move, a subject-wide logout landing
  // in the gap would find sess:{old} already gone and no breadcrumb to follow,
  // leaving the rotated session alive past revocation. Atomic here means a
  // concurrent logout sees either sess:{old} (EXISTS-gate fails closed) or
  // sess:{new}+breadcrumb (follows it) — never an in-between state.
  boolean rotateIfPresent(
      String oldKey,
      String newKey,
      String value,
      Duration ttl,
      String breadcrumbKey,
      String breadcrumbValue,
      Duration breadcrumbTtl);

  // Atomic compare-and-set: set key=newValue (with ttl) iff key currently equals
  // expected. Returns false (no-op) when the key is absent or holds a different
  // value. The sid-rotation index rekey uses this on idp_sid:{idpSid} so a
  // concurrent back-channel logout that cleared the index is not clobbered by the
  // rotation re-pointing it — if the CAS fails, the rotation aborts (fail closed).
  boolean compareAndSwap(String key, String expected, String newValue, Duration ttl);

  // Atomic compare-and-delete: delete key iff its current value equals expected,
  // returning true (false if the value differs or the key is absent). The
  // release side of a lease — an unconditional DEL could delete a lock another
  // instance acquired after ours expired by TTL; this deletes only a lock we
  // still own. Vendor-neutral: a Redis Lua GET==expected-then-DEL; the in-memory
  // twin uses an atomic compute. Used by DistributedRefreshKeyLock.
  boolean compareAndDelete(String key, String expected);

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

  // Atomic set-member swap-if-present: iff oldMember is in the set at key, replace
  // it with newMember and (re)set the key TTL, returning true; else a no-op
  // returning false. The set analogue of compareAndSwap. The sid-rotation
  // idp_sid:{idpSid} index — now a SET of local sids per OP session — uses this
  // to repoint a rotating member only if a concurrent back-channel logout has not
  // already removed it (or deleted the set); if the swap fails, the rotation
  // aborts (fail closed) rather than re-adding a member for a revoked session.
  boolean swapMemberIfPresent(String key, String oldMember, String newMember, Duration ttl);

  Set<String> members(String key);
}
