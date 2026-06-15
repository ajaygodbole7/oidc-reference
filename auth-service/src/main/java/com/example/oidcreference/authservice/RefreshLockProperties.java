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
 * <p>The distributed lease TTL must cover the whole guarded refresh action:
 * IdP connect timeout + IdP read timeout + local validation / rotation / GC
 * margin. {@link RefreshLockConfig} validates that cross-property budget when
 * distributed mode is selected.
 */
@Validated
@ConfigurationProperties(prefix = "app")
public record RefreshLockProperties(
    @NotBlank @DefaultValue("in-process") String refreshLock,
    @NotNull @DefaultValue("20s") Duration refreshLockTtl,
    @NotNull @DefaultValue("24s") Duration refreshLockMaxWait,
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
    // Validate the lease relationships, not just the mode. @NotNull only proves
    // the values were bound; it does not catch a misconfiguration that makes the
    // distributed lock unsafe — e.g. max-wait <= ttl (a crashed holder's lease
    // would not lapse within a contender's wait, so the contender always times
    // out) or poll >= max-wait (it would never poll). The defaults satisfy these;
    // an override that breaks them fails closed at boot, loudly.
    requirePositive("app.refresh-lock-ttl", refreshLockTtl);
    requirePositive("app.refresh-lock-max-wait", refreshLockMaxWait);
    requirePositive("app.refresh-lock-poll", refreshLockPoll);
    if (refreshLockMaxWait.compareTo(refreshLockTtl) <= 0) {
      throw new IllegalArgumentException(
          "app.refresh-lock-max-wait (" + refreshLockMaxWait + ") must be GREATER THAN "
              + "app.refresh-lock-ttl (" + refreshLockTtl + ") so a crashed holder's lease "
              + "lapses within a contender's wait");
    }
    if (refreshLockPoll.compareTo(refreshLockMaxWait) >= 0) {
      throw new IllegalArgumentException(
          "app.refresh-lock-poll (" + refreshLockPoll + ") must be LESS THAN "
              + "app.refresh-lock-max-wait (" + refreshLockMaxWait + ")");
    }
  }

  private static void requirePositive(String name, Duration value) {
    if (value == null || value.isZero() || value.isNegative()) {
      throw new IllegalArgumentException(name + " must be a positive duration, got: " + value);
    }
  }

  boolean distributed() {
    return "distributed".equalsIgnoreCase(refreshLock);
  }
}
