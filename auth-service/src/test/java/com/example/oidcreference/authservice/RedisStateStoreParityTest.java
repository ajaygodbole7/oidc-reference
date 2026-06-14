package com.example.oidcreference.authservice;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import java.time.Duration;
import java.util.List;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.data.redis.connection.RedisStandaloneConfiguration;
import org.springframework.data.redis.connection.lettuce.LettuceConnectionFactory;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.testcontainers.DockerClientFactory;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.utility.DockerImageName;

/**
 * Parity contract for the two atomic primitives A6 sid-rotation rides on —
 * {@code rotateIfPresent} and {@code compareAndSwap} — between the production
 * Redis/Lua implementation ({@link RedisStateStore}, run here against a real
 * {@code valkey} container matching compose) and the in-memory test twin
 * ({@link InMemoryStateStore}).
 *
 * <p>The live e2e exercises only the <b>happy</b> path: every real rotation runs
 * the Lua {@code EXISTS}-gate (success) and the {@code GET == expected} CAS
 * (success). The divergence risk the twin carries is entirely in the
 * <b>fail-closed</b> branches — old key absent, CAS expected-mismatch, CAS key
 * absent — which the e2e never reaches because each requires a concurrent logout
 * to win a race against an in-flight refresh. Those are exactly the branches
 * whose correctness the security argument depends on (do not resurrect a revoked
 * session; do not clobber a logout's index clear). This test pins them identical
 * across both stores, so a future twin edit or a Lua typo that diverges fails
 * here instead of silently in production.
 *
 * <p>Also asserts the Redis-only property the twin cannot model: rotate/CAS write
 * a key with a finite {@code PX} TTL, never a persistent key (a dropped
 * {@code PX} would leak a session past its absolute ceiling).
 *
 * <p>Requires Docker; <b>skips</b> (not fails) when Docker is unavailable so the
 * host unit loop stays Docker-free.
 */
class RedisStateStoreParityTest {

  // Match compose.yaml (valkey/valkey:9.1-alpine); declared Redis-compatible so
  // Testcontainers' wait strategy and the Lettuce client treat it as Redis.
  private static final DockerImageName VALKEY =
      DockerImageName.parse("valkey/valkey:9.1-alpine").asCompatibleSubstituteFor("redis");

  private static final Duration TTL = Duration.ofMinutes(30);

  private static GenericContainer<?> valkey;
  private static LettuceConnectionFactory connectionFactory;
  private static RedisStateStore redisStore;

  private final InMemoryStateStore memoryStore = new InMemoryStateStore();

  @BeforeAll
  static void startValkey() {
    assumeTrue(
        DockerClientFactory.instance().isDockerAvailable(),
        "Docker not available — skipping Redis/in-memory parity test");
    valkey = new GenericContainer<>(VALKEY).withExposedPorts(6379);
    valkey.start();
    var config = new RedisStandaloneConfiguration(valkey.getHost(), valkey.getFirstMappedPort());
    connectionFactory = new LettuceConnectionFactory(config);
    connectionFactory.afterPropertiesSet();
    var template = new StringRedisTemplate(connectionFactory);
    template.afterPropertiesSet();
    redisStore = new RedisStateStore(template);
  }

  @AfterAll
  static void stopValkey() {
    if (connectionFactory != null) {
      connectionFactory.destroy();
    }
    if (valkey != null) {
      valkey.stop();
    }
  }

  @BeforeEach
  void flush() {
    connectionFactory.getConnection().serverCommands().flushAll();
    memoryStore.clear();
  }

  // Assert both stores returned the same boolean AND left every named key in the
  // same state (present-with-value vs absent). Divergence on either fails here.
  private void assertSameOutcome(
      String scenario, boolean redisResult, boolean memResult, List<String> keys) {
    assertThat(redisResult).as(scenario + ": return-value parity").isEqualTo(memResult);
    for (String key : keys) {
      assertThat(redisStore.get(key))
          .as(scenario + ": post-state of '" + key + "' parity")
          .isEqualTo(memoryStore.get(key));
    }
  }

  // --- rotateIfPresent -------------------------------------------------------

  @Test
  void rotateIfPresent_oldPresent_movesValueAndWritesBreadcrumbAtomically() {
    redisStore.put("sess:old", "rec", TTL);
    memoryStore.put("sess:old", "rec", TTL);

    boolean r = redisStore.rotateIfPresent("sess:old", "sess:new", "rec2", TTL,
        "rotated:old", "new", TTL);
    boolean m = memoryStore.rotateIfPresent("sess:old", "sess:new", "rec2", TTL,
        "rotated:old", "new", TTL);

    assertSameOutcome("rotate/old-present", r, m,
        List.of("sess:old", "sess:new", "rotated:old"));
    assertThat(r).isTrue();
    assertThat(redisStore.get("sess:old")).as("old sid dropped").isEmpty();
    assertThat(redisStore.get("sess:new")).as("value moved to new sid").contains("rec2");
    // N3: the breadcrumb is written in the SAME atomic op as the move, so a logout
    // reaching the old sid after the move always finds it to follow through.
    assertThat(redisStore.get("rotated:old")).as("breadcrumb written atomically").contains("new");
  }

  @Test
  void rotateIfPresent_oldAbsent_failsClosed_writesNeitherSessionNorBreadcrumb() {
    // Fail-closed branch: a concurrent logout DEL'd sess:{old} mid-refresh. Neither
    // store may create sess:{new} (would resurrect a revoked session) NOR leave an
    // orphan breadcrumb pointing at a session that never existed.
    boolean r = redisStore.rotateIfPresent("sess:gone", "sess:new", "rec", TTL,
        "rotated:gone", "new", TTL);
    boolean m = memoryStore.rotateIfPresent("sess:gone", "sess:new", "rec", TTL,
        "rotated:gone", "new", TTL);

    assertSameOutcome("rotate/old-absent", r, m,
        List.of("sess:gone", "sess:new", "rotated:gone"));
    assertThat(r).isFalse();
    assertThat(redisStore.get("sess:new"))
        .as("a revoked session must NOT be resurrected under the new sid")
        .isEmpty();
    assertThat(redisStore.get("rotated:gone"))
        .as("no orphan breadcrumb when the rotation fails closed")
        .isEmpty();
  }

  @Test
  void rotateIfPresent_newKeyAlreadyPresent_overwrites() {
    redisStore.put("sess:old", "rec", TTL);
    redisStore.put("sess:new", "stale", TTL);
    memoryStore.put("sess:old", "rec", TTL);
    memoryStore.put("sess:new", "stale", TTL);

    boolean r = redisStore.rotateIfPresent("sess:old", "sess:new", "rec", TTL,
        "rotated:old", "new", TTL);
    boolean m = memoryStore.rotateIfPresent("sess:old", "sess:new", "rec", TTL,
        "rotated:old", "new", TTL);

    assertSameOutcome("rotate/new-pre-exists", r, m,
        List.of("sess:old", "sess:new", "rotated:old"));
    assertThat(redisStore.get("sess:new")).contains("rec");
  }

  // --- compareAndSwap --------------------------------------------------------

  @Test
  void compareAndSwap_matches_swapsAndReturnsTrue() {
    redisStore.put("idp_sid:k", "old", TTL);
    memoryStore.put("idp_sid:k", "old", TTL);

    boolean r = redisStore.compareAndSwap("idp_sid:k", "old", "new", TTL);
    boolean m = memoryStore.compareAndSwap("idp_sid:k", "old", "new", TTL);

    assertSameOutcome("cas/match", r, m, List.of("idp_sid:k"));
    assertThat(r).isTrue();
    assertThat(redisStore.get("idp_sid:k")).contains("new");
  }

  @Test
  void compareAndSwap_mismatch_failsClosed_doesNotClobber() {
    // A concurrent logout changed idp_sid since the refresh read it. The rotation's
    // CAS must not clobber that newer value — both stores leave it, return false.
    redisStore.put("idp_sid:k", "changed", TTL);
    memoryStore.put("idp_sid:k", "changed", TTL);

    boolean r = redisStore.compareAndSwap("idp_sid:k", "expected", "new", TTL);
    boolean m = memoryStore.compareAndSwap("idp_sid:k", "expected", "new", TTL);

    assertSameOutcome("cas/mismatch", r, m, List.of("idp_sid:k"));
    assertThat(r).isFalse();
    assertThat(redisStore.get("idp_sid:k"))
        .as("must not clobber the concurrent logout's write")
        .contains("changed");
  }

  @Test
  void compareAndSwap_keyAbsent_failsClosed_doesNotCreate() {
    // A concurrent logout cleared idp_sid entirely. GET returns nil != expected, so
    // neither store creates the key — the rotation aborts (fail closed).
    boolean r = redisStore.compareAndSwap("idp_sid:gone", "expected", "new", TTL);
    boolean m = memoryStore.compareAndSwap("idp_sid:gone", "expected", "new", TTL);

    assertSameOutcome("cas/key-absent", r, m, List.of("idp_sid:gone"));
    assertThat(r).isFalse();
    assertThat(redisStore.get("idp_sid:gone"))
        .as("a CAS on an absent key must not create it")
        .isEmpty();
  }

  // --- swapMemberIfPresent (set analogue of compareAndSwap) ------------------

  @Test
  void swapMemberIfPresent_memberPresent_swapsAndReturnsTrue() {
    redisStore.addToSet("idp_sid:k", "old", TTL);
    memoryStore.addToSet("idp_sid:k", "old", TTL);

    boolean r = redisStore.swapMemberIfPresent("idp_sid:k", "old", "new", TTL);
    boolean m = memoryStore.swapMemberIfPresent("idp_sid:k", "old", "new", TTL);

    assertThat(r).as("return-value parity").isEqualTo(m);
    assertThat(r).isTrue();
    assertThat(redisStore.members("idp_sid:k"))
        .as("member parity")
        .containsExactlyInAnyOrderElementsOf(memoryStore.members("idp_sid:k"))
        .containsExactly("new");
  }

  @Test
  void swapMemberIfPresent_memberAbsentOtherMembersRemain_failsClosed() {
    // Another local session for the same OP sid remains; this session's member was
    // removed by a concurrent logout. The swap must fail and leave the survivor —
    // the rotation aborts rather than re-adding a member for the revoked session.
    redisStore.addToSet("idp_sid:k", "other", TTL);
    memoryStore.addToSet("idp_sid:k", "other", TTL);

    boolean r = redisStore.swapMemberIfPresent("idp_sid:k", "old", "new", TTL);
    boolean m = memoryStore.swapMemberIfPresent("idp_sid:k", "old", "new", TTL);

    assertThat(r).as("return-value parity").isEqualTo(m);
    assertThat(r).isFalse();
    assertThat(redisStore.members("idp_sid:k"))
        .as("member parity; new not added, surviving member kept")
        .containsExactlyInAnyOrderElementsOf(memoryStore.members("idp_sid:k"))
        .containsExactly("other");
  }

  @Test
  void swapMemberIfPresent_setAbsent_failsClosed_doesNotCreate() {
    // A concurrent logout deleted the whole set. Neither store recreates it.
    boolean r = redisStore.swapMemberIfPresent("idp_sid:gone", "old", "new", TTL);
    boolean m = memoryStore.swapMemberIfPresent("idp_sid:gone", "old", "new", TTL);

    assertThat(r).as("return-value parity").isEqualTo(m);
    assertThat(r).isFalse();
    assertThat(redisStore.members("idp_sid:gone"))
        .as("a swap on an absent set must not create it")
        .isEmpty();
    assertThat(memoryStore.members("idp_sid:gone")).isEmpty();
  }

  // --- compareAndDelete (DistributedRefreshKeyLock release) -----------------

  @Test
  void compareAndDelete_match_deletesAndReturnsTrue() {
    redisStore.put("refresh_lock:s", "token-A", TTL);
    memoryStore.put("refresh_lock:s", "token-A", TTL);

    boolean r = redisStore.compareAndDelete("refresh_lock:s", "token-A");
    boolean m = memoryStore.compareAndDelete("refresh_lock:s", "token-A");

    assertSameOutcome("cad/match", r, m, List.of("refresh_lock:s"));
    assertThat(r).isTrue();
    assertThat(redisStore.get("refresh_lock:s")).as("own lease released").isEmpty();
  }

  @Test
  void compareAndDelete_mismatch_doesNotDeleteAnotherHoldersLease() {
    // Our lease expired by TTL and another instance acquired the lock (token-B).
    // Releasing must NOT delete the lock we no longer own.
    redisStore.put("refresh_lock:s", "token-B", TTL);
    memoryStore.put("refresh_lock:s", "token-B", TTL);

    boolean r = redisStore.compareAndDelete("refresh_lock:s", "token-A");
    boolean m = memoryStore.compareAndDelete("refresh_lock:s", "token-A");

    assertSameOutcome("cad/mismatch", r, m, List.of("refresh_lock:s"));
    assertThat(r).isFalse();
    assertThat(redisStore.get("refresh_lock:s"))
        .as("must not delete a lease held by another instance")
        .contains("token-B");
  }

  @Test
  void compareAndDelete_keyAbsent_isNoOpReturningFalse() {
    boolean r = redisStore.compareAndDelete("refresh_lock:gone", "token-A");
    boolean m = memoryStore.compareAndDelete("refresh_lock:gone", "token-A");

    assertSameOutcome("cad/key-absent", r, m, List.of("refresh_lock:gone"));
    assertThat(r).isFalse();
  }

  // --- Redis-only: the written key must carry a finite PX TTL -----------------

  @Test
  void rotateAndCas_writeAFiniteTtl_notAPersistentKey() {
    // The twin trivially stores the Duration; the real risk is a Lua that forgot
    // PX, leaving a persistent key that outlives the session's absolute ceiling.
    redisStore.put("sess:old", "rec", TTL);
    redisStore.rotateIfPresent("sess:old", "sess:new", "rec", Duration.ofSeconds(120),
        "rotated:old", "new", Duration.ofSeconds(10));
    assertThat(redisStore.ttl("sess:new"))
        .as("rotate must SET ... PX, never a persistent key")
        .isBetween(Duration.ofSeconds(90), Duration.ofSeconds(120));
    assertThat(redisStore.ttl("rotated:old"))
        .as("breadcrumb gets its own (shorter) PX grace TTL")
        .isBetween(Duration.ofSeconds(1), Duration.ofSeconds(10));

    redisStore.put("idp_sid:k", "old", TTL);
    redisStore.compareAndSwap("idp_sid:k", "old", "new", Duration.ofSeconds(120));
    assertThat(redisStore.ttl("idp_sid:k"))
        .as("CAS must SET ... PX, never a persistent key")
        .isBetween(Duration.ofSeconds(90), Duration.ofSeconds(120));
  }
}
