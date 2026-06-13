package com.example.oidcreference.authservice;

import java.time.Duration;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Value;
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
 * <p>The distributed lease TTL defaults above the IdP connect+read budget
 * ({@code app.idp-connect-timeout} + {@code app.idp-read-timeout}, 3s+5s) so the
 * lease covers a full refresh round-trip; {@code max-wait} defaults above the TTL
 * so a crashed holder's lease always lapses within a contender's wait.
 */
@Configuration
class RefreshLockConfig {
  private static final Logger log = LoggerFactory.getLogger(RefreshLockConfig.class);

  @Bean
  RefreshLock refreshLock(
      @Value("${app.refresh-lock:in-process}") String mode,
      @Value("${app.refresh-lock-ttl:10s}") Duration ttl,
      @Value("${app.refresh-lock-max-wait:12s}") Duration maxWait,
      @Value("${app.refresh-lock-poll:50ms}") Duration poll,
      ObjectProvider<StateStore> stateStore) {
    if ("distributed".equalsIgnoreCase(mode)) {
      log.info("RefreshLock: distributed (ttl={}, maxWait={}, poll={})", ttl, maxWait, poll);
      return new DistributedRefreshKeyLock(stateStore.getObject(), ttl, maxWait, poll);
    }
    log.info("RefreshLock: in-process (single-instance only)");
    return new InProcessRefreshLock();
  }
}
