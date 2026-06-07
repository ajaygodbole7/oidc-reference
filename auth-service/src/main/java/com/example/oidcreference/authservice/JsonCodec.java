package com.example.oidcreference.authservice;

import org.springframework.stereotype.Component;
import tools.jackson.core.JacksonException;
import tools.jackson.databind.json.JsonMapper;

@Component
class JsonCodec {
  private final JsonMapper mapper;

  JsonCodec(JsonMapper mapper) {
    this.mapper = mapper;
  }

  String encode(Object value) {
    try {
      return mapper.writeValueAsString(value);
    } catch (JacksonException e) {
      throw new SessionCodecException("failed to encode state-store value", e);
    }
  }

  <T> T decode(String value, Class<T> type) {
    try {
      return mapper.readValue(value, type);
    } catch (JacksonException e) {
      throw new SessionCodecException("failed to decode state-store value", e);
    }
  }

  /**
   * Wraps Jackson failures from the Auth Service's transaction- and
   * session-state codec path so callers can distinguish persistence-format
   * failures from generic {@code IllegalStateException}s thrown elsewhere in
   * the flow.
   */
  static final class SessionCodecException extends RuntimeException {
    SessionCodecException(String message, Throwable cause) {
      super(message, cause);
    }
  }
}
