package com.example.oidcreference.authservice;

import com.nimbusds.jwt.JWTParser;
import java.time.Duration;
import java.util.LinkedHashSet;
import java.util.Optional;
import java.util.Set;
import org.springframework.stereotype.Component;

@Component
class SessionIndexes {
  private static final String SESSION_PREFIX = "sess:";
  private static final String IDP_SID_PREFIX = "idp_sid:";
  private static final String SUBJECT_SESSIONS_PREFIX = "sub_sessions:";

  private final StateStore stateStore;
  private final JsonCodec json;

  SessionIndexes(StateStore stateStore, JsonCodec json) {
    this.stateStore = stateStore;
    this.json = json;
  }

  void index(String localSid, SessionRecord session, Duration ttl) {
    idpSid(session).ifPresent(idpSid ->
        stateStore.put(IDP_SID_PREFIX + idpSid, localSid, ttl));
    subject(session).ifPresent(sub ->
        addSubjectSession(sub, localSid, ttl));
  }

  boolean deleteByIdpSid(String idpSid) {
    Optional<String> localSid = stateStore.getAndDelete(IDP_SID_PREFIX + idpSid);
    localSid.ifPresent(this::deleteLocalSession);
    return localSid.isPresent();
  }

  int deleteBySubject(String sub) {
    Optional<String> encoded = stateStore.getAndDelete(SUBJECT_SESSIONS_PREFIX + sub);
    if (encoded.isEmpty()) {
      return 0;
    }
    int deleted = 0;
    for (String localSid : decodeSidSet(encoded.get())) {
      if (deleteLocalSession(localSid)) {
        deleted++;
      }
    }
    return deleted;
  }

  boolean deleteLocalSession(String localSid) {
    Optional<SessionRecord> session = stateStore.get(SESSION_PREFIX + localSid)
        .map(value -> json.decode(value, SessionRecord.class));
    stateStore.delete(SESSION_PREFIX + localSid);
    if (session.isEmpty()) {
      return false;
    }
    idpSid(session.get()).ifPresent(idpSid ->
        stateStore.delete(IDP_SID_PREFIX + idpSid));
    subject(session.get()).ifPresent(sub ->
        removeSubjectSession(sub, localSid));
    return true;
  }

  private void addSubjectSession(String sub, String localSid, Duration ttl) {
    var key = SUBJECT_SESSIONS_PREFIX + sub;
    Set<String> sids = stateStore.get(key)
        .map(SessionIndexes::decodeSidSet)
        .orElseGet(LinkedHashSet::new);
    sids.add(localSid);
    stateStore.put(key, encodeSidSet(sids), ttl);
  }

  private void removeSubjectSession(String sub, String localSid) {
    var key = SUBJECT_SESSIONS_PREFIX + sub;
    Optional<String> encoded = stateStore.get(key);
    if (encoded.isEmpty()) {
      return;
    }
    Set<String> sids = decodeSidSet(encoded.get());
    if (sids.size() == 1 && sids.contains(localSid)) {
      stateStore.delete(key);
    }
  }

  private static Optional<String> subject(SessionRecord session) {
    Object sub = session.claims() == null ? null : session.claims().get("sub");
    if (sub == null || sub.toString().isBlank()) {
      return Optional.empty();
    }
    return Optional.of(sub.toString());
  }

  static Optional<String> idpSid(SessionRecord session) {
    if (session.idToken() == null || session.idToken().isBlank()) {
      return Optional.empty();
    }
    try {
      Object sid = JWTParser.parse(session.idToken()).getJWTClaimsSet().getClaim("sid");
      if (sid == null || sid.toString().isBlank()) {
        return Optional.empty();
      }
      return Optional.of(sid.toString());
    } catch (Exception e) {
      return Optional.empty();
    }
  }

  private static LinkedHashSet<String> decodeSidSet(String encoded) {
    LinkedHashSet<String> result = new LinkedHashSet<>();
    if (encoded == null || encoded.isBlank()) {
      return result;
    }
    for (String line : encoded.split("\\n")) {
      if (!line.isBlank()) {
        result.add(line);
      }
    }
    return result;
  }

  private static String encodeSidSet(Set<String> sids) {
    return String.join("\n", sids);
  }
}
