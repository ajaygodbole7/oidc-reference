package com.example.oidcreference.authservice;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.time.Duration;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;

/**
 * Drives {@link DistributedRefreshKeyLock} against the vendor-neutral
 * {@link StateStore} abstraction (here the in-memory twin — the lock depends
 * only on {@code putIfAbsent} / {@code compareAndDelete}, never on a Redis or
 * Valkey client, so this runs with no container). Real Redis Lua parity for the
 * underlying primitives lives in {@code RedisStateStoreParityTest}.
 */
class DistributedRefreshKeyLockTest {

  private final StateStore store = new InMemoryStateStore();
  private final RefreshLock lock = new DistributedRefreshKeyLock(
      store, Duration.ofSeconds(5), Duration.ofSeconds(5), Duration.ofMillis(5));

  @Test
  void serializesConcurrentCallersOnTheSameKey() throws Exception {
    // Two callers on the same sid must NOT run the action concurrently: the
    // second blocks until the first releases. (With no real lock, both run at
    // once and maxInFlight reaches 2 — the red this test was written against.)
    AtomicInteger inFlight = new AtomicInteger();
    AtomicInteger maxInFlight = new AtomicInteger();
    Runnable body = () -> lock.withLock("sid-1", () -> {
      int now = inFlight.incrementAndGet();
      maxInFlight.accumulateAndGet(now, Math::max);
      sleep(120);
      inFlight.decrementAndGet();
      return null;
    });

    runConcurrently(body, body);

    assertThat(maxInFlight.get()).as("the action never runs concurrently for one key").isEqualTo(1);
  }

  @Test
  void differentKeysDoNotBlockEachOther() throws Exception {
    // Per-key locking: two different sids proceed in parallel.
    AtomicInteger inFlight = new AtomicInteger();
    AtomicInteger maxInFlight = new AtomicInteger();
    Runnable a = () -> lock.withLock("sid-a", () -> { tick(inFlight, maxInFlight); return null; });
    Runnable b = () -> lock.withLock("sid-b", () -> { tick(inFlight, maxInFlight); return null; });

    runConcurrently(a, b);

    assertThat(maxInFlight.get()).as("distinct keys are not serialized against each other").isEqualTo(2);
  }

  @Test
  void releasesLockSoTheNextCallerProceeds() {
    assertThat(lock.withLock("sid-2", () -> "first")).isEqualTo("first");
    // The lease must be gone after the action, or the next caller would block out.
    assertThat(store.get("refresh_lock:sid-2")).isEmpty();
    assertThat(lock.withLock("sid-2", () -> "second")).isEqualTo("second");
  }

  @Test
  void releasesLockEvenWhenTheActionThrows() {
    assertThatThrownBy(() -> lock.withLock("sid-3", () -> {
      throw new IllegalStateException("boom");
    })).isInstanceOf(IllegalStateException.class).hasMessage("boom");
    assertThat(store.get("refresh_lock:sid-3")).as("lease released on throw").isEmpty();
  }

  @Test
  void returnsTheActionResult() {
    assertThat(lock.withLock("sid-4", () -> 42)).isEqualTo(42);
  }

  private static void tick(AtomicInteger inFlight, AtomicInteger maxInFlight) {
    int now = inFlight.incrementAndGet();
    maxInFlight.accumulateAndGet(now, Math::max);
    sleep(120);
    inFlight.decrementAndGet();
  }

  private static void runConcurrently(Runnable... tasks) throws Exception {
    ExecutorService pool = Executors.newFixedThreadPool(tasks.length);
    CountDownLatch start = new CountDownLatch(1);
    var futures = new java.util.ArrayList<java.util.concurrent.Future<?>>();
    for (Runnable t : tasks) {
      futures.add(pool.submit(() -> {
        await(start);
        t.run();
      }));
    }
    start.countDown();
    for (var f : futures) {
      f.get(10, TimeUnit.SECONDS);
    }
    pool.shutdownNow();
  }

  private static void await(CountDownLatch latch) {
    try {
      latch.await();
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
      throw new IllegalStateException(e);
    }
  }

  private static void sleep(long millis) {
    try {
      Thread.sleep(millis);
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
      throw new IllegalStateException(e);
    }
  }
}
