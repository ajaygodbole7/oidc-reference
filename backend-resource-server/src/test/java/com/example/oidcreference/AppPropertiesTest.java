package com.example.oidcreference;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.time.Duration;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.springframework.boot.context.properties.bind.Bindable;
import org.springframework.boot.context.properties.bind.Binder;
import org.springframework.boot.context.properties.source.ConfigurationPropertySources;
import org.springframework.core.env.MapPropertySource;
import org.springframework.core.env.MutablePropertySources;

// Unit-tests the AppProperties binding contract: a valid config binds with the
// nested step-up block; the cross-field invariant fails fast; and a blank
// required-acr normalizes to empty (the "IdP emits no acr" path).
class AppPropertiesTest {

  private static AppProperties bind(Map<String, Object> properties) {
    MutablePropertySources sources = new MutablePropertySources();
    sources.addFirst(new MapPropertySource("test", properties));
    Binder binder = new Binder(ConfigurationPropertySources.from(sources));
    return binder.bind("app", Bindable.of(AppProperties.class)).get();
  }

  private static Map<String, Object> validConfig() {
    return new java.util.HashMap<>(Map.of(
        "app.audience", "oidc-reference-api",
        "app.roles-claim-path", "realm_access,roles",
        "app.service-client-ids", "oidc-reference-api-gateway,oidc-reference-service",
        "app.jobs-client-id", "oidc-reference-service",
        "app.step-up.max-age", "300s",
        "app.step-up.required-acr", "1"));
  }

  @Test
  void validConfigBinds() {
    AppProperties props = bind(validConfig());
    assertThat(props.audience()).isEqualTo("oidc-reference-api");
    assertThat(props.rolesClaimPath()).containsExactly("realm_access", "roles");
    assertThat(props.serviceClientIds())
        .containsExactlyInAnyOrder("oidc-reference-api-gateway", "oidc-reference-service");
    assertThat(props.jobsClientId()).isEqualTo("oidc-reference-service");
    assertThat(props.stepUp().maxAge()).isEqualTo(Duration.ofSeconds(300));
    assertThat(props.stepUp().requiredAcr()).containsExactly("1");
  }

  @Test
  void crossFieldInvariantFailsFastWhenJobsClientIsOutsideAllowlist() {
    Map<String, Object> config = validConfig();
    config.put("app.jobs-client-id", "not-in-allowlist");
    assertThatThrownBy(() -> bind(config))
        .hasRootCauseInstanceOf(IllegalArgumentException.class)
        .rootCause()
        .hasMessageContaining("app.jobs-client-id");
  }

  @Test
  void blankRequiredAcrNormalizesToEmpty() {
    Map<String, Object> config = validConfig();
    config.put("app.step-up.required-acr", "");
    AppProperties props = bind(config);
    assertThat(props.stepUp().requiredAcr()).isEmpty();
  }

  @Test
  void requiredAcrStripsBlankEntries() {
    Map<String, Object> config = validConfig();
    config.put("app.step-up.required-acr", List.of("1", " ", "2"));
    AppProperties props = bind(config);
    assertThat(props.stepUp().requiredAcr()).containsExactlyInAnyOrder("1", "2");
  }
}
