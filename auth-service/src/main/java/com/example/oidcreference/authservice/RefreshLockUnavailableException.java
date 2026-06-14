package com.example.oidcreference.authservice;

/**
 * Thrown by a {@link RefreshLock} when it cannot acquire the per-session lock
 * (the distributed lock failing to acquire within {@code max-wait}, a store error
 * while acquiring, or an interrupt) — so the caller fails closed rather than
 * running the refresh unguarded.
 *
 * <p>Distinct type on purpose: {@code InternalResolveController} catches THIS to
 * map a lock-acquire failure to a transient 503, and must NOT catch a failure
 * from the locked action ({@code refreshUnderLock}, which maps its own outcomes),
 * or it would mislabel an unrelated error (e.g. a store WRONGTYPE) as
 * "lock unavailable". The in-process lock never throws this.
 */
class RefreshLockUnavailableException extends RuntimeException {
  RefreshLockUnavailableException(String message) {
    super(message);
  }

  RefreshLockUnavailableException(String message, Throwable cause) {
    super(message, cause);
  }
}
