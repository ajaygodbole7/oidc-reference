package com.example.oidcreference.authservice;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.stream.IntStream;
import org.junit.jupiter.api.Test;

class SessionIndexesTest {

  private static final JsonCodec JSON = new JsonCodec(
      tools.jackson.databind.json.JsonMapper.builder().findAndAddModules().build());

  private static SessionRecord sessionForSubject(String sub) {
    Instant now = Instant.now();
    return new SessionRecord(
        "access-token",
        "refresh-token",
        null, // no id_token -> only the subject index is written
        now.plusSeconds(300),
        now.plusSeconds(1800),
        now,
        now.plusSeconds(28800),
        now,
        Map.of("sub", sub));
  }

  @Test
  void concurrentLoginsForOneSubjectDoNotLoseSidsFromTheSubjectIndex() throws Exception {
    // The subject index (sub_sessions:{sub}) backs sub-based back-channel
    // logout. The prior newline-encoded GET-decode-add-PUT lost members under
    // concurrent logins for the same subject (last writer wins). With atomic
    // set semantics (Redis SADD / ConcurrentHashMap set) every concurrent add
    // must survive. 32 logins for alice fire simultaneously off a start gate.
    InMemoryStateStore store = new InMemoryStateStore();
    SessionIndexes indexes = new SessionIndexes(store, JSON);
    int n = 32;
    CountDownLatch start = new CountDownLatch(1);
    ExecutorService pool = Executors.newFixedThreadPool(8);
    try {
      var futures = IntStream.range(0, n)
          .mapToObj(i -> pool.submit(() -> {
            try {
              start.await();
            } catch (InterruptedException e) {
              Thread.currentThread().interrupt();
              throw new IllegalStateException(e);
            }
            indexes.index("local-sid-" + i, sessionForSubject("alice"));
          }))
          .toList();
      start.countDown();
      for (var f : futures) {
        f.get(10, TimeUnit.SECONDS);
      }
    } finally {
      pool.shutdownNow();
    }

    assertThat(store.members("sub_sessions:alice"))
        .as("every concurrent login must be recorded in the subject index — no lost updates")
        .hasSize(n)
        .containsExactlyInAnyOrderElementsOf(
            IntStream.range(0, n).mapToObj(i -> "local-sid-" + i).toList());
  }

  @Test
  void removingASubjectSessionDropsOnlyThatMember() {
    InMemoryStateStore store = new InMemoryStateStore();
    SessionIndexes indexes = new SessionIndexes(store, JSON);
    // deleteLocalSession reads sess:{sid} to find the subject, so the record
    // must exist (as it does in production).
    SessionRecord first = sessionForSubject("alice");
    SessionRecord second = sessionForSubject("alice");
    store.put("sess:local-sid-1", JSON.encode(first), Duration.ofMinutes(30));
    indexes.index("local-sid-1", first);
    store.put("sess:local-sid-2", JSON.encode(second), Duration.ofMinutes(30));
    indexes.index("local-sid-2", second);

    // Deleting one local session SREMs just its member from the subject index.
    indexes.deleteLocalSession("local-sid-1");

    assertThat(store.members("sub_sessions:alice")).containsExactly("local-sid-2");
  }

  @Test
  void corruptSessionRecordIsStillDeletable() {
    // A sess:{sid} whose JSON is unparseable (truncated write, schema drift)
    // must still be evictable — otherwise logout 500s and the poisoned key
    // lingers until its TTL. deleteLocalSession must delete the key first and
    // tolerate a decode failure (it just can't clean the secondary indexes,
    // which is acceptable — the session is gone).
    InMemoryStateStore store = new InMemoryStateStore();
    SessionIndexes indexes = new SessionIndexes(store, JSON);
    store.put("sess:corrupt-1", "{not-valid-json", Duration.ofMinutes(30));

    boolean deleted = indexes.deleteLocalSession("corrupt-1");

    assertThat(store.get("sess:corrupt-1"))
        .as("a corrupt session record must still be removable")
        .isEmpty();
    assertThat(deleted)
        .as("no SessionRecord could be decoded, so no indexes were cleaned")
        .isFalse();
  }

  @Test
  void deleteBySubjectRemovesEveryLocalSessionAndTheIndex() {
    InMemoryStateStore store = new InMemoryStateStore();
    SessionIndexes indexes = new SessionIndexes(store, JSON);
    store.put("sess:local-sid-1", JSON.encode(sessionForSubject("alice")), Duration.ofMinutes(30));
    indexes.index("local-sid-1", sessionForSubject("alice"));
    store.put("sess:local-sid-2", JSON.encode(sessionForSubject("alice")), Duration.ofMinutes(30));
    indexes.index("local-sid-2", sessionForSubject("alice"));

    int deleted = indexes.deleteBySubject("alice");

    assertThat(deleted).isEqualTo(2);
    assertThat(store.get("sess:local-sid-1")).isEmpty();
    assertThat(store.get("sess:local-sid-2")).isEmpty();
    assertThat(store.members("sub_sessions:alice")).isEmpty();
  }

  @Test
  void deleteByIdpSidDeletesAllLocalSessionsForOneOpSid() {
    // Two local sessions (e.g. two BFF logins while one Keycloak SSO session
    // persists) resolve to the SAME OP sid. A back-channel logout by that sid
    // must terminate BOTH; the prior scalar idp_sid index kept only the last
    // writer, so the first session survived revocation.
    InMemoryStateStore store = new InMemoryStateStore();
    SessionIndexes indexes = new SessionIndexes(store, JSON);
    SessionRecord first = sessionWithIdpSid("alice", "kc-1");
    SessionRecord second = sessionWithIdpSid("alice", "kc-1");
    store.put("sess:local-1", JSON.encode(first), Duration.ofMinutes(30));
    indexes.index("local-1", first);
    store.put("sess:local-2", JSON.encode(second), Duration.ofMinutes(30));
    indexes.index("local-2", second);

    int deleted = indexes.deleteByIdpSid("kc-1");

    assertThat(deleted).as("both local sessions for the OP sid are deleted").isEqualTo(2);
    assertThat(store.get("sess:local-1")).isEmpty();
    assertThat(store.get("sess:local-2")).isEmpty();
    assertThat(store.members("idp_sid:kc-1")).isEmpty();
  }

  @Test
  void deleteByIdpSidDrainsASessionAddedAfterTheFirstSnapshot() {
    // A fresh login can add a local sid to idp_sid:{opSid} while a back-channel
    // logout is draining the same OP sid. The index must not be deleted up front:
    // the drain must re-read and catch the late member, or the new sess:{sid}
    // survives the logout.
    SessionRecord late = sessionWithIdpSid("alice", "kc-1");
    InMemoryStateStore store = new AddAfterFirstMembersStore(
        "idp_sid:kc-1", "late", late, JSON);
    SessionIndexes indexes = new SessionIndexes(store, JSON);
    SessionRecord first = sessionWithIdpSid("alice", "kc-1");
    store.put("sess:first", JSON.encode(first), Duration.ofMinutes(30));
    indexes.index("first", first);

    int deleted = indexes.deleteByIdpSid("kc-1");

    assertThat(deleted).isEqualTo(2);
    assertThat(store.get("sess:first")).isEmpty();
    assertThat(store.get("sess:late")).isEmpty();
    assertThat(store.members("idp_sid:kc-1")).isEmpty();
  }

  @Test
  void deleteBySubjectDrainsASessionAddedAfterTheFirstSnapshot() {
    SessionRecord late = sessionForSubject("alice");
    InMemoryStateStore store = new AddAfterFirstMembersStore(
        "sub_sessions:alice", "late", late, JSON);
    SessionIndexes indexes = new SessionIndexes(store, JSON);
    SessionRecord first = sessionForSubject("alice");
    store.put("sess:first", JSON.encode(first), Duration.ofMinutes(30));
    indexes.index("first", first);

    int deleted = indexes.deleteBySubject("alice");

    assertThat(deleted).isEqualTo(2);
    assertThat(store.get("sess:first")).isEmpty();
    assertThat(store.get("sess:late")).isEmpty();
    assertThat(store.members("sub_sessions:alice")).isEmpty();
  }

  @Test
  void deleteByIdpSidRetryCanStillFindSessionsAfterPartialDeleteFailure() {
    // The replay marker is written only after deletion succeeds. That only helps
    // if a retry can still enumerate the index after a mid-loop store failure.
    // Keeping the index live until members are removed makes the retry safe.
    InMemoryStateStore store = new FailOnceDeletingSessionStore("local-1");
    SessionIndexes indexes = new SessionIndexes(store, JSON);
    SessionRecord session = sessionWithIdpSid("alice", "kc-1");
    store.put("sess:local-1", JSON.encode(session), Duration.ofMinutes(30));
    indexes.index("local-1", session);

    org.assertj.core.api.Assertions.assertThatThrownBy(() -> indexes.deleteByIdpSid("kc-1"))
        .isInstanceOf(IllegalStateException.class)
        .hasMessageContaining("injected delete failure");
    assertThat(store.get("sess:local-1")).isPresent();
    assertThat(store.members("idp_sid:kc-1")).containsExactly("local-1");

    int deleted = indexes.deleteByIdpSid("kc-1");

    assertThat(deleted).isEqualTo(1);
    assertThat(store.get("sess:local-1")).isEmpty();
    assertThat(store.members("idp_sid:kc-1")).isEmpty();
  }

  @Test
  void drainRemovesCorruptIndexMembersAndStillDeletesReadableSiblings() {
    InMemoryStateStore store = new InMemoryStateStore();
    SessionIndexes indexes = new SessionIndexes(store, JSON);
    SessionRecord good = sessionForSubject("alice");
    store.put("sess:good", JSON.encode(good), Duration.ofMinutes(30));
    indexes.index("good", good);
    store.put("sess:corrupt", "{not-json", Duration.ofMinutes(30));
    store.addToSet("sub_sessions:alice", "corrupt", Duration.ofMinutes(30));

    int deleted = indexes.deleteBySubject("alice");

    assertThat(deleted).isEqualTo(1);
    assertThat(store.get("sess:good")).isEmpty();
    assertThat(store.get("sess:corrupt")).isEmpty();
    assertThat(store.members("sub_sessions:alice"))
        .as("explicit SREM makes progress even when sess:{sid} cannot be decoded")
        .isEmpty();
  }

  @Test
  void drainFailsClosedWhenConcurrentAddsNeverQuiesce() {
    InMemoryStateStore store = new AddOnEveryMembersStore(
        "sub_sessions:alice", "storm", sessionForSubject("alice"), JSON);
    SessionIndexes indexes = new SessionIndexes(store, JSON);
    SessionRecord first = sessionForSubject("alice");
    store.put("sess:first", JSON.encode(first), Duration.ofMinutes(30));
    indexes.index("first", first);

    org.assertj.core.api.Assertions.assertThatThrownBy(() -> indexes.deleteBySubject("alice"))
        .isInstanceOf(IllegalStateException.class)
        .hasMessageContaining("session index drain incomplete");
  }

  @Test
  void aLateShortLivedSessionDoesNotShrinkTheSubjectIndexTtl() {
    // sub_sessions:{sub} is shared across a subject's sessions and TTL'd by each
    // session's remaining absolute lifetime. A later short-lived session must
    // NOT pull the index TTL below a still-live longer session — otherwise the
    // index expires first and a subject-wide logout misses the live session.
    // The fix is an extend-only TTL on addToSet.
    InMemoryStateStore store = new InMemoryStateStore();
    SessionIndexes indexes = new SessionIndexes(store, JSON);
    SessionRecord longLived = sessionWithAbsoluteExpiry("alice", Instant.now().plusSeconds(3600));
    store.put("sess:s1", JSON.encode(longLived), Duration.ofSeconds(3600));
    indexes.index("s1", longLived);
    SessionRecord shortLived = sessionWithAbsoluteExpiry("alice", Instant.now().plusSeconds(10));
    store.put("sess:s2", JSON.encode(shortLived), Duration.ofSeconds(10));
    indexes.index("s2", shortLived);

    assertThat(store.ttl("sub_sessions:alice"))
        .as("the subject index TTL must not shrink below the long-lived session")
        .isGreaterThan(Duration.ofSeconds(60));
    assertThat(store.members("sub_sessions:alice")).containsExactlyInAnyOrder("s1", "s2");
  }

  // --- A6: sid rotation (rotate) + the breadcrumb-follow on logout -----------

  @Test
  void rotateRepointsAllThreeIndexesWhenIdpSidMatches() {
    InMemoryStateStore store = new InMemoryStateStore();
    SessionIndexes indexes = new SessionIndexes(store, JSON);
    SessionRecord session = sessionWithIdpSid("alice", "kc-1");
    indexes.index("old", session);
    assertThat(store.members("idp_sid:kc-1")).containsExactly("old");

    boolean rotated = indexes.rotate("old", "new", session);

    assertThat(rotated).isTrue();
    assertThat(store.members("idp_sid:kc-1")).as("idp_sid repointed").containsExactly("new");
    assertThat(store.members("sub_sessions:alice")).containsExactly("new");
    assertThat(store.get("logout_hint:new")).isPresent();
    assertThat(store.get("logout_hint:old")).isEmpty();
  }

  @Test
  void rotateDoesNotShrinkSharedIdpSidTtlBelowALiveSibling() {
    // Two local sessions share one OP sid (idp_sid:kc-shared is a SET). The
    // long-lived one sets the shared TTL high. Rotating the SHORT-lived sibling
    // must NOT shrink the shared idp_sid TTL below the long-lived session — else
    // idp_sid expires first and a back-channel logout by OP sid misses the live
    // session. The fix is an extend-only TTL on swapMemberIfPresent (the rotation
    // repoint), the same property addToSet already has for sub_sessions.
    InMemoryStateStore store = new InMemoryStateStore();
    SessionIndexes indexes = new SessionIndexes(store, JSON);
    Instant now = Instant.now();
    SessionRecord longLived = new SessionRecord(
        "access-token", "refresh-token", jwtWithSid("kc-shared"),
        now.plusSeconds(300), now.plusSeconds(1800), now,
        now.plusSeconds(3600), now, Map.of("sub", "alice"));
    SessionRecord shortLived = new SessionRecord(
        "access-token", "refresh-token", jwtWithSid("kc-shared"),
        now.plusSeconds(300), now.plusSeconds(1800), now,
        now.plusSeconds(10), now, Map.of("sub", "alice"));
    indexes.index("long", longLived);
    indexes.index("short", shortLived);
    assertThat(store.members("idp_sid:kc-shared")).containsExactlyInAnyOrder("long", "short");

    boolean rotated = indexes.rotate("short", "short-new", shortLived);

    assertThat(rotated).isTrue();
    assertThat(store.members("idp_sid:kc-shared")).containsExactlyInAnyOrder("long", "short-new");
    assertThat(store.ttl("idp_sid:kc-shared"))
        .as("rotating the short-lived sibling must not shrink the shared idp_sid TTL")
        .isGreaterThan(Duration.ofSeconds(60));
  }

  @Test
  void rotateWithoutIdpSidStillSucceedsAndMovesSubjectIndex() {
    // No id_token / sid claim (a portability shape) -> no idp_sid CAS to engage;
    // rotation must still proceed and move the subject index.
    InMemoryStateStore store = new InMemoryStateStore();
    SessionIndexes indexes = new SessionIndexes(store, JSON);
    SessionRecord session = sessionForSubject("alice"); // idToken == null
    indexes.index("old", session);

    boolean rotated = indexes.rotate("old", "new", session);

    assertThat(rotated).isTrue();
    assertThat(store.members("sub_sessions:alice")).containsExactly("new");
  }

  @Test
  void rotateFailsClosedWhenIdpSidClearedByConcurrentLogout() {
    // A concurrent back-channel logout cleared idp_sid before the rekey CAS runs.
    InMemoryStateStore store = new InMemoryStateStore();
    SessionIndexes indexes = new SessionIndexes(store, JSON);
    SessionRecord session = sessionWithIdpSid("alice", "kc-1");
    indexes.index("old", session);
    store.delete("idp_sid:kc-1"); // logout already cleared the whole set

    boolean rotated = indexes.rotate("old", "new", session);

    assertThat(rotated).as("swap-if-present fails -> rotation aborts").isFalse();
    assertThat(store.members("idp_sid:kc-1")).as("not resurrected by the rotation").isEmpty();
  }

  @Test
  void rotateFailsClosedWhenRotatingMemberRemovedByConcurrentLogout() {
    // A concurrent logout removed THIS session's member from the idp_sid set
    // (other sessions for the same OP sid may remain). The rotation must not
    // re-add the rotated sid for the now-revoked session.
    InMemoryStateStore store = new InMemoryStateStore();
    SessionIndexes indexes = new SessionIndexes(store, JSON);
    SessionRecord session = sessionWithIdpSid("alice", "kc-1");
    indexes.index("old", session);
    store.removeFromSet("idp_sid:kc-1", "old"); // logout removed just this member

    boolean rotated = indexes.rotate("old", "new", session);

    assertThat(rotated).as("swap-if-present fails -> rotation aborts").isFalse();
    assertThat(store.members("idp_sid:kc-1"))
        .as("the revoked session's rotated sid is not re-added")
        .doesNotContain("new");
  }

  @Test
  void deleteLocalSessionFollowsTheRotationBreadcrumb() {
    // Subject-path logout race: a logout reaching only the OLD sid must also
    // delete the session that rotated out from under it (sess:{new}), via the
    // rotated:{old} breadcrumb.
    InMemoryStateStore store = new InMemoryStateStore();
    SessionIndexes indexes = new SessionIndexes(store, JSON);
    store.put("sess:new", JSON.encode(sessionForSubject("alice")), Duration.ofMinutes(30));
    indexes.index("new", sessionForSubject("alice"));
    store.put("rotated:old", "new", Duration.ofSeconds(30));

    indexes.deleteLocalSession("old"); // logout reached the old sid only

    assertThat(store.get("sess:new")).as("rotated-to session killed via breadcrumb").isEmpty();
    assertThat(store.get("rotated:old")).as("breadcrumb consumed").isEmpty();
    assertThat(store.members("sub_sessions:alice")).isEmpty();
  }

  private static String jwtWithSid(String idpSid) {
    var enc = java.util.Base64.getUrlEncoder().withoutPadding();
    var utf8 = java.nio.charset.StandardCharsets.UTF_8;
    return enc.encodeToString("{\"alg\":\"HS256\"}".getBytes(utf8)) + "."
        + enc.encodeToString(("{\"sid\":\"" + idpSid + "\"}").getBytes(utf8)) + ".sig";
  }

  private static SessionRecord sessionWithAbsoluteExpiry(String sub, Instant absoluteExpiresAt) {
    Instant now = Instant.now();
    return new SessionRecord(
        "access-token", "refresh-token", null,
        now.plusSeconds(300), now.plusSeconds(1800), now,
        absoluteExpiresAt, now, Map.of("sub", sub));
  }

  private static SessionRecord sessionWithIdpSid(String sub, String idpSid) {
    Instant now = Instant.now();
    return new SessionRecord(
        "access-token", "refresh-token", jwtWithSid(idpSid),
        now.plusSeconds(300), now.plusSeconds(1800), now,
        now.plusSeconds(28800), now, Map.of("sub", sub));
  }

  private static final class AddAfterFirstMembersStore extends InMemoryStateStore {
    private final String indexKey;
    private final String lateSid;
    private final SessionRecord lateSession;
    private final JsonCodec json;
    private final AtomicBoolean injected = new AtomicBoolean();

    private AddAfterFirstMembersStore(
        String indexKey,
        String lateSid,
        SessionRecord lateSession,
        JsonCodec json) {
      this.indexKey = indexKey;
      this.lateSid = lateSid;
      this.lateSession = lateSession;
      this.json = json;
    }

    @Override
    public Set<String> members(String key) {
      Set<String> snapshot = super.members(key);
      if (indexKey.equals(key) && injected.compareAndSet(false, true)) {
        super.put("sess:" + lateSid, json.encode(lateSession), Duration.ofMinutes(30));
        super.addToSet(indexKey, lateSid, Duration.ofMinutes(30));
      }
      return snapshot;
    }
  }

  private static final class FailOnceDeletingSessionStore extends InMemoryStateStore {
    private final String sid;
    private final AtomicBoolean failed = new AtomicBoolean();

    private FailOnceDeletingSessionStore(String sid) {
      this.sid = sid;
    }

    @Override
    public void delete(String key) {
      if (("sess:" + sid).equals(key) && failed.compareAndSet(false, true)) {
        throw new IllegalStateException("injected delete failure");
      }
      super.delete(key);
    }
  }

  private static final class AddOnEveryMembersStore extends InMemoryStateStore {
    private final String indexKey;
    private final String sidPrefix;
    private final SessionRecord session;
    private final JsonCodec json;
    private int counter;

    private AddOnEveryMembersStore(
        String indexKey,
        String sidPrefix,
        SessionRecord session,
        JsonCodec json) {
      this.indexKey = indexKey;
      this.sidPrefix = sidPrefix;
      this.session = session;
      this.json = json;
    }

    @Override
    public Set<String> members(String key) {
      Set<String> snapshot = super.members(key);
      if (indexKey.equals(key) && counter < 10) {
        String sid = sidPrefix + "-" + counter++;
        super.put("sess:" + sid, json.encode(session), Duration.ofMinutes(30));
        super.addToSet(indexKey, sid, Duration.ofMinutes(30));
      }
      return snapshot;
    }
  }
}
