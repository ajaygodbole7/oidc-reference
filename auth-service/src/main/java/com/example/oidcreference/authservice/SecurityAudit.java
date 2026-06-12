package com.example.oidcreference.authservice;

import jakarta.servlet.http.HttpServletRequest;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

// Structured audit-log helper. Emits via a dedicated logger named
// "security.audit". Shape mirrors the Resource Server's audit line so
// downstream log pipelines can parse a single grammar across services:
//
//   security_audit event=<name> status=<code> method=<...> path=<...>
//                  reason=<code> [sub_hash=<hash>] remote=<addr>
//
// Subject hashing: the user's `sub` claim is a stable identifier; raw
// values in long-lived audit logs are a PII-grade concern for a
// reference targeting fintech / internal-platform reuse. We emit a
// truncated SHA-256 hex digest instead — enough entropy to correlate
// events for the same user inside an investigation window, without
// publishing the raw subject. The hash is unsalted and not a reversible
// pseudonym; if you need cross-incident correlation with reversibility,
// route raw subjects through a separate, access-controlled pipeline.
//
// Callers MUST NOT pass tokens, sids, cookie values, or secrets.
final class SecurityAudit {
  private static final Logger LOG = LoggerFactory.getLogger("security.audit");

  // The audit wire format, declared in ONE place. The ~20 test assertions that
  // pin substrings like "event=" / "reason=" and any downstream log-pipeline
  // grammar depend on this shape; changing the wire format (e.g. moving to JSON
  // structured logging) means editing these two constants and the single
  // SecurityAuditTest that owns the rendered-shape invariant, not 20 call sites.
  // The placeholders are SLF4J {} parameter slots filled, in order, by the
  // event(...) methods below.
  static final String FORMAT =
      "security_audit event={} status={} method={} path={} reason={} remote={}";
  static final String FORMAT_WITH_SUBJECT =
      "security_audit event={} status={} method={} path={} reason={} sub_hash={} remote={}";

  // 24 hex chars = 96 bits. The previous 16-char (64-bit) hash hit
  // birthday-bound collision at ~4B subjects, which would complicate
  // incident-response correlation in a tenant with millions of users.
  // 96 bits pushes the collision threshold to ~2^48 subjects.
  private static final int SUB_HASH_HEX_CHARS = 24;
  private static final char[] HEX = "0123456789abcdef".toCharArray();

  private SecurityAudit() {}

  static void event(HttpServletRequest request, int status, String event, String reason) {
    LOG.info(
        FORMAT,
        event,
        status,
        method(request),
        path(request),
        reason,
        remote(request));
  }

  static void event(
      HttpServletRequest request, int status, String event, String reason, String sub) {
    LOG.info(
        FORMAT_WITH_SUBJECT,
        event,
        status,
        method(request),
        path(request),
        reason,
        truncatedSha256Hex(sub),
        remote(request));
  }

  private static String method(HttpServletRequest request) {
    return request == null ? "-" : request.getMethod();
  }

  private static String path(HttpServletRequest request) {
    return request == null ? "-" : request.getRequestURI();
  }

  private static String remote(HttpServletRequest request) {
    return request == null ? "-" : request.getRemoteAddr();
  }

  // Truncated SHA-256 of a sensitive identifier (subject or sid).
  // Reusing the same function across event types means a log analyst
  // correlating across the audit stream only needs to know one
  // hashing convention. Returns "-" for null/blank so the log shape
  // stays parseable. The raw value never goes into any log.
  static String hashSid(String sid) {
    return truncatedSha256Hex(sid);
  }

  private static String truncatedSha256Hex(String value) {
    if (value == null || value.isBlank()) {
      return "-";
    }
    try {
      MessageDigest md = MessageDigest.getInstance("SHA-256");
      byte[] digest = md.digest(value.getBytes(StandardCharsets.UTF_8));
      StringBuilder sb = new StringBuilder(SUB_HASH_HEX_CHARS);
      for (int i = 0; i < SUB_HASH_HEX_CHARS / 2; i++) {
        int b = digest[i] & 0xff;
        sb.append(HEX[b >>> 4]).append(HEX[b & 0xf]);
      }
      return sb.toString();
    } catch (NoSuchAlgorithmException e) {
      // SHA-256 is guaranteed by the JRE; this never fires.
      return "-";
    }
  }
}
