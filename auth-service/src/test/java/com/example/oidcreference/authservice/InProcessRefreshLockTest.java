package com.example.oidcreference.authservice;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.concurrent.CountDownLatch;
import java.util.concurrent.CyclicBarrier;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;

/**
 * Unit tests for the default per-JVM {@link RefreshLock}. These pin the
 * properties {@code InternalResolveController} relies on to collapse concurrent
 * refreshes: same-key mutual exclusion, distinct-key independence,
 * reference-counted cleanup (no unbounded map growth), and release-on-throw.
 */
class InProcessRefreshLockTest {

  @Test
  void returnsTheActionResult() {
    RefreshLock lock = new InProcessRefreshLock();
    assertThat(lock.withLock("k", () -> 42)).isEqualTo(42);
  }

  @Test
  void sameKeyRunsAreMutuallyExclusive() throws Exception {
    InProcessRefreshLock lock = new InProcessRefreshLock();
    int threads = 8;
    AtomicInteger inside = new AtomicInteger();
    AtomicInteger maxObserved = new AtomicInteger();
    CountDownLatch start = new CountDownLatch(1);
    CountDownLatch done = new CountDownLatch(threads);
    ExecutorService pool = Executors.newFixedThreadPool(threads);
    try {
      for (int i = 0; i < threads; i++) {
        pool.submit(
            () -> {
              await(start);
              lock.withLock(
                  "same",
                  () -> {
                    int now = inside.incrementAndGet();
                    maxObserved.accumulateAndGet(now, Math::max);
                    sleepQuietly(5);
                    inside.decrementAndGet();
                    return null;
                  });
              done.countDown();
            });
      }
      start.countDown();
      assertThat(done.await(10, TimeUnit.SECONDS)).isTrue();
    } finally {
      pool.shutdownNow();
    }
    assertThat(maxObserved.get())
        .as("at most one thread inside the lock for a given key at a time")
        .isEqualTo(1);
    assertThat(lock.trackedKeys()).as("entry cleaned up after all holders release").isZero();
  }

  @Test
  void distinctKeysDoNotBlockEachOther() throws Exception {
    RefreshLock lock = new InProcessRefreshLock();
    // Each thread enters its own key's lock and waits for the other at the
    // barrier. If distinct keys shared a lock, one could never enter while the
    // other holds it and the barrier would time out.
    CyclicBarrier bothInside = new CyclicBarrier(2);
    ExecutorService pool = Executors.newFixedThreadPool(2);
    try {
      var a = pool.submit(() -> lock.withLock("A", () -> awaitBarrier(bothInside)));
      var b = pool.submit(() -> lock.withLock("B", () -> awaitBarrier(bothInside)));
      assertThat(a.get(5, TimeUnit.SECONDS)).isTrue();
      assertThat(b.get(5, TimeUnit.SECONDS)).isTrue();
    } finally {
      pool.shutdownNow();
    }
  }

  @Test
  void releasesAndCleansUpWhenTheActionThrows() {
    InProcessRefreshLock lock = new InProcessRefreshLock();
    assertThatThrownBy(
            () ->
                lock.withLock(
                    "x",
                    () -> {
                      throw new IllegalStateException("boom");
                    }))
        .isInstanceOf(IllegalStateException.class)
        .hasMessage("boom");
    // Lock was released despite the throw: a subsequent acquire succeeds, and
    // the map entry was cleaned up.
    assertThat(lock.withLock("x", () -> "ok")).isEqualTo("ok");
    assertThat(lock.trackedKeys()).isZero();
  }

  private static boolean awaitBarrier(CyclicBarrier barrier) {
    try {
      barrier.await(5, TimeUnit.SECONDS);
      return true;
    } catch (Exception e) {
      return false;
    }
  }

  private static void await(CountDownLatch latch) {
    try {
      latch.await();
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
    }
  }

  private static void sleepQuietly(long millis) {
    try {
      Thread.sleep(millis);
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
    }
  }
}
