package com.example.oidcreference.authservice;

import com.nimbusds.jwt.JWTParser;
import java.time.Duration;
import java.time.Instant;
import java.util.Optional;
import java.util.Set;
import org.springframework.stereotype.Component;

@Component
class SessionIndexes {
  private static final String SESSION_PREFIX = "sess:";
  private static final String IDP_SID_PREFIX = "idp_sid:";
  private static final String SUBJECT_SESSIONS_PREFIX = "sub_sessions:";
  private static final String LOGOUT_HINT_PREFIX = "logout_hint:";
  // Forward-pointer left by a sid rotation (A6, set by InternalResolveController).
  // A logout follows it so it cannot be outrun by a concurrent refresh-rotation.
  private static final String ROTATED_PREFIX = "rotated:";

  private final StateStore stateStore;
  private final JsonCodec json;

  SessionIndexes(StateStore stateStore, JsonCodec json) {
    this.stateStore = stateStore;
    this.json = json;
  }

  // Index TTL is the session's remaining ABSOLUTE lifetime, not the idle
  // TTL. The Auth Service slides only sess:{sid} (in /internal/resolve) and
  // rewrites only the session key; nothing re-extends these index keys. An idle TTL
  // here would expire them after the first idle window, silently turning
  // IdP back-channel logout into a 200 "no_matching_session" for any
  // longer-lived session — the exact stolen-cookie revocation case the
  // indexes exist for. The asymmetry is safe in one direction only: an
  // index entry outliving a dead sess: key is harmless (the delete paths
  // tolerate a missing session); the reverse is a logout bypass.
  void index(String localSid, SessionRecord session) {
    Duration ttl = Duration.between(Instant.now(), session.absoluteExpiresAt());
    if (ttl.isNegative() || ttl.isZero()) {
      return;
    }
    idpSid(session).ifPresent(idpSid ->
        stateStore.addToSet(IDP_SID_PREFIX + idpSid, localSid, ttl));
    subject(session).ifPresent(sub ->
        addSubjectSession(sub, localSid, ttl));
    if (session.idToken() != null && !session.idToken().isBlank()) {
      stateStore.put(LOGOUT_HINT_PREFIX + localSid, session.idToken(), ttl);
    }
  }

  // Repoint the secondary indexes from oldSid to newSid after a sid rotation on
  // refresh. A refresh does NOT change the IdP session id — only the LOCAL sid
  // moves. Returns false iff a concurrent back-channel logout has already cleared
  // (or changed) idp_sid:{idpSid} — i.e. the session was revoked mid-rotation;
  // the caller must then fail closed (undo the rotation) rather than let this
  // method resurrect a revoked session by rebuilding its indexes.
  //
  // The idp_sid repoint is a set swap-if-present (only if oldSid is still a
  // member): without it, the rotation's unconditional re-add would clobber a
  // logout's removal, undoing the revocation. sub_sessions add-before-removes (the
  // subject is always represented by a live sid), and the logout hint moves. Index
  // TTL is the remaining absolute lifetime, exactly as index().
  boolean rotate(String oldSid, String newSid, SessionRecord session) {
    Duration ttl = Duration.between(Instant.now(), session.absoluteExpiresAt());
    if (ttl.isNegative() || ttl.isZero()) {
      return false;
    }
    Optional<String> idpSid = idpSid(session);
    if (idpSid.isPresent()
        && !stateStore.swapMemberIfPresent(IDP_SID_PREFIX + idpSid.get(), oldSid, newSid, ttl)) {
      // A concurrent logout removed oldSid from idp_sid (or deleted the set)
      // since the refresh started.
      return false;
    }
    subject(session).ifPresent(sub -> {
      addSubjectSession(sub, newSid, ttl);
      removeSubjectSession(sub, oldSid);
    });
    stateStore.delete(LOGOUT_HINT_PREFIX + oldSid);
    if (session.idToken() != null && !session.idToken().isBlank()) {
      stateStore.put(LOGOUT_HINT_PREFIX + newSid, session.idToken(), ttl);
    }
    return true;
  }

  Optional<String> consumeLogoutHint(String localSid) {
    return stateStore.getAndDelete(LOGOUT_HINT_PREFIX + localSid);
  }

  // idp_sid:{idpSid} is a SET of local sids: one OP session can back several
  // local sessions (e.g. repeated BFF logins while the IdP SSO session persists),
  // and a back-channel logout by OP sid must terminate ALL of them. Mirrors
  // deleteBySubject: snapshot the members, drop the index, delete each session.
  int deleteByIdpSid(String idpSid) {
    var key = IDP_SID_PREFIX + idpSid;
    Set<String> localSids = stateStore.members(key);
    if (localSids.isEmpty()) {
      return 0;
    }
    stateStore.delete(key);
    int deleted = 0;
    for (String localSid : localSids) {
      if (deleteLocalSession(localSid)) {
        deleted++;
      }
    }
    return deleted;
  }

  int deleteBySubject(String sub) {
    var key = SUBJECT_SESSIONS_PREFIX + sub;
    Set<String> localSids = stateStore.members(key);
    if (localSids.isEmpty()) {
      return 0;
    }
    // Drop the index up front: each deleteLocalSession below also SREMs the
    // member, but removing the key now bounds the work to the snapshot and
    // leaves no empty index behind.
    stateStore.delete(key);
    int deleted = 0;
    for (String localSid : localSids) {
      if (deleteLocalSession(localSid)) {
        deleted++;
      }
    }
    return deleted;
  }

  boolean deleteLocalSession(String localSid) {
    // Decode defensively, then delete UNCONDITIONALLY. A corrupt sess:{sid}
    // value (truncated write, schema drift) must still be evictable — decoding
    // before the delete would let a parse failure abort the whole logout and
    // strand the poisoned key. We lose only the secondary-index cleanup for a
    // record we cannot read, which is acceptable: those indexes carry their own
    // TTL and tolerate a dangling pointer.
    Optional<SessionRecord> session = stateStore.get(SESSION_PREFIX + localSid)
        .flatMap(this::tryDecode);
    stateStore.delete(SESSION_PREFIX + localSid);
    stateStore.delete(LOGOUT_HINT_PREFIX + localSid);
    // Follow a rotation breadcrumb: if this sid rotated to a new sid mid-flight (a
    // concurrent refresh-rotation), the LIVE session is now under the new sid — so
    // a logout that reached only the old sid must delete the new one too, or a
    // subject-wide logout (deleteBySubject, not lock-serialized) could be undone by
    // the rotation re-adding the new sid to sub_sessions. getAndDelete consumes the
    // breadcrumb, so a rotation chain terminates. The rotation writes sess:{new}
    // AND this breadcrumb in ONE atomic op (StateStore.rotateIfPresent, N3), so
    // there is no window where the new session exists without a breadcrumb to
    // follow: a concurrent logout sees either sess:{old} (and the rotation's
    // EXISTS-gate then fails closed) or sess:{new}+breadcrumb (and this follow
    // kills it) — never an in-between state.
    stateStore.getAndDelete(ROTATED_PREFIX + localSid)
        .ifPresent(this::deleteLocalSession);
    if (session.isEmpty()) {
      return false;
    }
    idpSid(session.get()).ifPresent(idpSid ->
        stateStore.removeFromSet(IDP_SID_PREFIX + idpSid, localSid));
    subject(session.get()).ifPresent(sub ->
        removeSubjectSession(sub, localSid));
    return true;
  }

  private Optional<SessionRecord> tryDecode(String value) {
    try {
      return Optional.of(json.decode(value, SessionRecord.class));
    } catch (RuntimeException e) {
      return Optional.empty();
    }
  }

  private void addSubjectSession(String sub, String localSid, Duration ttl) {
    // SADD is atomic per member — concurrent logins for the same subject
    // cannot lose a sid to a read-decode-modify-write race (the prior
    // newline-encoded GET/PUT could).
    stateStore.addToSet(SUBJECT_SESSIONS_PREFIX + sub, localSid, ttl);
  }

  private void removeSubjectSession(String sub, String localSid) {
    stateStore.removeFromSet(SUBJECT_SESSIONS_PREFIX + sub, localSid);
  }

  private static Optional<String> subject(SessionRecord session) {
    Object sub = session.claims() == null ? null : session.claims().get("sub");
    if (sub == null || sub.toString().isBlank()) {
      return Optional.empty();
    }
    return Optional.of(sub.toString());
  }

  static Optional<String> idpSid(SessionRecord session) {
    Optional<String> fromIdToken = sidFromJwt(session.idToken());
    if (fromIdToken.isPresent()) {
      return fromIdToken;
    }
    return sidFromJwt(session.accessToken());
  }

  private static Optional<String> sidFromJwt(String token) {
    if (token == null || token.isBlank()) {
      return Optional.empty();
    }
    try {
      Object sid = JWTParser.parse(token).getJWTClaimsSet().getClaim("sid");
      if (sid == null || sid.toString().isBlank()) {
        return Optional.empty();
      }
      return Optional.of(sid.toString());
    } catch (Exception e) {
      return Optional.empty();
    }
  }

}
