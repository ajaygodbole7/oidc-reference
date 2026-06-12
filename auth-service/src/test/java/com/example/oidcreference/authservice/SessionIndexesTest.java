package com.example.oidcreference.authservice;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
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

  // --- A6: sid rotation (rotate) + the breadcrumb-follow on logout -----------

  @Test
  void rotateRepointsAllThreeIndexesWhenIdpSidMatches() {
    InMemoryStateStore store = new InMemoryStateStore();
    SessionIndexes indexes = new SessionIndexes(store, JSON);
    SessionRecord session = sessionWithIdpSid("alice", "kc-1");
    indexes.index("old", session);
    assertThat(store.get("idp_sid:kc-1")).contains("old");

    boolean rotated = indexes.rotate("old", "new", session);

    assertThat(rotated).isTrue();
    assertThat(store.get("idp_sid:kc-1")).as("idp_sid repointed").contains("new");
    assertThat(store.members("sub_sessions:alice")).containsExactly("new");
    assertThat(store.get("logout_hint:new")).isPresent();
    assertThat(store.get("logout_hint:old")).isEmpty();
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
    store.delete("idp_sid:kc-1"); // logout already cleared it

    boolean rotated = indexes.rotate("old", "new", session);

    assertThat(rotated).as("CAS fails -> rotation aborts").isFalse();
    assertThat(store.get("idp_sid:kc-1")).as("not resurrected by the rotation").isEmpty();
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

  private static SessionRecord sessionWithIdpSid(String sub, String idpSid) {
    Instant now = Instant.now();
    return new SessionRecord(
        "access-token", "refresh-token", jwtWithSid(idpSid),
        now.plusSeconds(300), now.plusSeconds(1800), now,
        now.plusSeconds(28800), now, Map.of("sub", sub));
  }
}
