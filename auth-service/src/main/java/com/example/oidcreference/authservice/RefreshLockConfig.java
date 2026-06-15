package com.example.oidcreference.authservice;

import java.time.Duration;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * Selects the {@link RefreshLock} implementation by configuration so the
 * single-instance default and the horizontally-scaled variant are a one-line
 * config flip, not a code change.
 *
 * <ul>
 *   <li>{@code app.refresh-lock=in-process} (default) — {@link InProcessRefreshLock},
 *       correct for the single-instance local reference.</li>
 *   <li>{@code app.refresh-lock=distributed} — {@link DistributedRefreshKeyLock}
 *       over the shared {@link StateStore}; required before running more than one
 *       Auth Service instance (see {@code docs/operations/production-hardening.md}).</li>
 * </ul>
 *
 * <p>The distributed lease TTL must cover the whole guarded refresh action:
 * IdP connect timeout + IdP read timeout + local validation / rotation / GC
 * margin. We validate that budget at boot when distributed mode is selected, so
 * scaling out cannot silently reintroduce the double-refresh race.
 */
@Configuration
class RefreshLockConfig {
  private static final Logger log = LoggerFactory.getLogger(RefreshLockConfig.class);
  static final Duration DISTRIBUTED_REFRESH_ACTION_MARGIN = Duration.ofSeconds(5);

  @Bean
  RefreshLock refreshLock(
      RefreshLockProperties properties,
      AuthProperties authProperties,
      ObjectProvider<StateStore> stateStore) {
    if (properties.distributed()) {
      validateDistributedLeaseBudget(
          properties.refreshLockTtl(),
          authProperties.idpConnectTimeout(),
          authProperties.idpReadTimeout());
      log.info("RefreshLock: distributed (ttl={}, maxWait={}, poll={})",
          properties.refreshLockTtl(), properties.refreshLockMaxWait(), properties.refreshLockPoll());
      return new DistributedRefreshKeyLock(
          stateStore.getObject(),
          properties.refreshLockTtl(),
          properties.refreshLockMaxWait(),
          properties.refreshLockPoll());
    }
    log.info("RefreshLock: in-process (single-instance only)");
    return new InProcessRefreshLock();
  }

  static void validateDistributedLeaseBudget(
      Duration lockTtl,
      Duration idpConnectTimeout,
      Duration idpReadTimeout) {
    Duration minimum = idpConnectTimeout
        .plus(idpReadTimeout)
        .plus(DISTRIBUTED_REFRESH_ACTION_MARGIN);
    if (lockTtl.compareTo(minimum) <= 0) {
      throw new IllegalArgumentException(
          "app.refresh-lock-ttl (" + lockTtl + ") must be greater than "
              + "app.idp-connect-timeout + app.idp-read-timeout + "
              + DISTRIBUTED_REFRESH_ACTION_MARGIN + " margin (" + minimum + ") "
              + "because DistributedRefreshKeyLock does not renew leases while the refresh "
              + "action is running");
    }
  }
}
