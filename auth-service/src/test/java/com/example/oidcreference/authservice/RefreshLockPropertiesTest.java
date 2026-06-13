package com.example.oidcreference.authservice;

import static org.assertj.core.api.Assertions.assertThat;

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
    assertThat(props.refreshLockTtl()).isEqualTo(Duration.ofSeconds(10));
    assertThat(props.refreshLockMaxWait()).isEqualTo(Duration.ofSeconds(12));
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
}
