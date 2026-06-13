/**
 * Auth Service module. {@code @NullMarked}: every type-usage in this package is
 * non-null unless explicitly annotated {@code @Nullable}. The deliberate
 * nullability that was previously carried only in prose comments (tolerant-read
 * record fields written before a schema addition, optional OIDC endpoints,
 * subject-claim lookups that can miss, optional {@code @RequestParam}s) is now
 * encoded in the type system for auditability.
 */
@org.jspecify.annotations.NullMarked
package com.example.oidcreference.authservice;
