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
}
