package com.example.oidcreference.authservice;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import java.time.Duration;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;
import org.springframework.validation.annotation.Validated;

/**
 * Typed model for the {@code app.refresh-lock*} cluster that selects and tunes
 * the {@link RefreshLock} implementation, replacing the {@code @Value} cluster
 * in {@link RefreshLockConfig}. The keys are flat (siblings under {@code app},
 * not a nested {@code app.refresh-lock.*} block) because {@code app.refresh-lock}
 * is itself the scalar mode value, so this binds at {@code prefix="app"} with
 * relaxed binding mapping {@code app.refresh-lock-ttl} → {@code refreshLockTtl}.
 *
 * <ul>
 *   <li>{@code app.refresh-lock=in-process} (default) — {@link InProcessRefreshLock}.</li>
 *   <li>{@code app.refresh-lock=distributed} — {@link DistributedRefreshKeyLock}.</li>
 * </ul>
 *
 * <p>Defaults match the previous self-documenting {@code @Value} defaults: the
 * distributed lease TTL sits above the IdP connect+read budget (3s+5s) so the
 * lease covers a full refresh round-trip; {@code maxWait} sits above the TTL so
 * a crashed holder's lease always lapses within a contender's wait.
 */
@Validated
@ConfigurationProperties(prefix = "app")
public record RefreshLockProperties(
    @NotBlank @DefaultValue("in-process") String refreshLock,
    @NotNull @DefaultValue("10s") Duration refreshLockTtl,
    @NotNull @DefaultValue("12s") Duration refreshLockMaxWait,
    @NotNull @DefaultValue("50ms") Duration refreshLockPoll) {

  // Reject an unrecognized mode at boot. distributed() treats any non-
  // "distributed" value as in-process, so a typo (app.refresh-lock=Redis) would
  // otherwise SILENTLY drop cross-instance coordination — the exact failure the
  // distributed lock exists to prevent. Fail fast and loud instead.
  public RefreshLockProperties {
    if (refreshLock != null
        && !"in-process".equalsIgnoreCase(refreshLock)
        && !"distributed".equalsIgnoreCase(refreshLock)) {
      throw new IllegalArgumentException(
          "app.refresh-lock must be 'in-process' or 'distributed' (case-insensitive), got: "
              + refreshLock);
    }
  }

  boolean distributed() {
    return "distributed".equalsIgnoreCase(refreshLock);
  }
}
