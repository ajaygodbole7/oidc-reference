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

  private final StateStore stateStore;
  private final JsonCodec json;

  SessionIndexes(StateStore stateStore, JsonCodec json) {
    this.stateStore = stateStore;
    this.json = json;
  }

  // Index TTL is the session's remaining ABSOLUTE lifetime, not the idle
  // TTL. The gateway slides only sess:{sid} and /internal/refresh rewrites
  // only the session key; nothing re-extends these index keys. An idle TTL
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
        stateStore.put(IDP_SID_PREFIX + idpSid, localSid, ttl));
    subject(session).ifPresent(sub ->
        addSubjectSession(sub, localSid, ttl));
    if (session.idToken() != null && !session.idToken().isBlank()) {
      stateStore.put(LOGOUT_HINT_PREFIX + localSid, session.idToken(), ttl);
    }
  }

  Optional<String> consumeLogoutHint(String localSid) {
    return stateStore.getAndDelete(LOGOUT_HINT_PREFIX + localSid);
  }

  boolean deleteByIdpSid(String idpSid) {
    Optional<String> localSid = stateStore.getAndDelete(IDP_SID_PREFIX + idpSid);
    localSid.ifPresent(this::deleteLocalSession);
    return localSid.isPresent();
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
    if (session.isEmpty()) {
      return false;
    }
    idpSid(session.get()).ifPresent(idpSid ->
        stateStore.delete(IDP_SID_PREFIX + idpSid));
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
