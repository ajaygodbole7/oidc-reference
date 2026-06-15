package com.example.oidcreference.authservice;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.time.Duration;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.springframework.boot.context.properties.bind.Bindable;
import org.springframework.boot.context.properties.bind.Binder;
import org.springframework.boot.context.properties.source.ConfigurationPropertySources;
import org.springframework.core.env.MapPropertySource;
import org.springframework.core.env.MutablePropertySources;

// Unit-tests the RefreshLockProperties binding: the flat app.refresh-lock*
// keys relaxed-bind onto the record, the self-documenting defaults survive an
// empty config, and distributed() selects on the mode.
class RefreshLockPropertiesTest {

  private static RefreshLockProperties bind(Map<String, Object> properties) {
    MutablePropertySources sources = new MutablePropertySources();
    sources.addFirst(new MapPropertySource("test", properties));
    Binder binder = new Binder(ConfigurationPropertySources.from(sources));
    return binder.bindOrCreate("app", Bindable.of(RefreshLockProperties.class));
  }

  @Test
  void defaultsApplyWhenUnset() {
    RefreshLockProperties props = bind(Map.of());
    assertThat(props.refreshLock()).isEqualTo("in-process");
    assertThat(props.distributed()).isFalse();
    assertThat(props.refreshLockTtl()).isEqualTo(Duration.ofSeconds(20));
    assertThat(props.refreshLockMaxWait()).isEqualTo(Duration.ofSeconds(24));
    assertThat(props.refreshLockPoll()).isEqualTo(Duration.ofMillis(50));
  }

  @Test
  void flatKeysRelaxedBindAndDistributedModeSelects() {
    RefreshLockProperties props = bind(Map.of(
        "app.refresh-lock", "distributed",
        "app.refresh-lock-ttl", "20s",
        "app.refresh-lock-max-wait", "25s",
        "app.refresh-lock-poll", "100ms"));
    assertThat(props.refreshLock()).isEqualTo("distributed");
    assertThat(props.distributed()).isTrue();
    assertThat(props.refreshLockTtl()).isEqualTo(Duration.ofSeconds(20));
    assertThat(props.refreshLockMaxWait()).isEqualTo(Duration.ofSeconds(25));
    assertThat(props.refreshLockPoll()).isEqualTo(Duration.ofMillis(100));
  }

  @Test
  void unrecognizedModeIsRejectedAtBinding() {
    // A typo'd mode (e.g. "redis") must FAIL FAST at boot, not silently fall
    // back to in-process — a silent fallback would drop cross-instance refresh
    // coordination, the exact failure the distributed lock exists to prevent.
    assertThatThrownBy(() -> bind(Map.of("app.refresh-lock", "redis")))
        .hasRootCauseInstanceOf(IllegalArgumentException.class)
        .rootCause()
        .hasMessageContaining("app.refresh-lock");
  }

  @Test
  void maxWaitNotGreaterThanTtlIsRejected() {
    // max-wait must EXCEED the lease TTL so a crashed holder's lease lapses
    // within a contender's wait; equal would mean the contender always times out.
    assertThatThrownBy(() -> bind(Map.of(
        "app.refresh-lock", "distributed",
        "app.refresh-lock-ttl", "10s",
        "app.refresh-lock-max-wait", "10s")))
        .hasRootCauseInstanceOf(IllegalArgumentException.class)
        .rootCause()
        .hasMessageContaining("max-wait");
  }

  @Test
  void pollNotLessThanMaxWaitIsRejected() {
    assertThatThrownBy(() -> bind(Map.of(
        "app.refresh-lock", "distributed",
        "app.refresh-lock-ttl", "10s",
        "app.refresh-lock-max-wait", "12s",
        "app.refresh-lock-poll", "12s")))
        .hasRootCauseInstanceOf(IllegalArgumentException.class)
        .rootCause()
        .hasMessageContaining("poll");
  }

  @Test
  void nonPositiveTtlIsRejected() {
    assertThatThrownBy(() -> bind(Map.of(
        "app.refresh-lock", "distributed",
        "app.refresh-lock-ttl", "0s")))
        .hasRootCauseInstanceOf(IllegalArgumentException.class)
        .rootCause()
        .hasMessageContaining("ttl");
  }

  @Test
  void distributedLeaseMustCoverIdpRoundTripPlusMargin() {
    // DistributedRefreshKeyLock has no watchdog/lease renewal. The lease must
    // cover the whole protected action: IdP connect + IdP read + local
    // validation/rotation/GC margin. Otherwise another instance can acquire the
    // lock while the first refresh is still running and double-spend the refresh token.
    assertThatThrownBy(() -> RefreshLockConfig.validateDistributedLeaseBudget(
            Duration.ofSeconds(13),
            Duration.ofSeconds(3),
            Duration.ofSeconds(5)))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("app.refresh-lock-ttl");
  }

  @Test
  void defaultDistributedLeaseCoversDefaultIdpTimeoutsPlusMargin() {
    RefreshLockConfig.validateDistributedLeaseBudget(
        Duration.ofSeconds(20),
        Duration.ofSeconds(3),
        Duration.ofSeconds(5));
  }
}
