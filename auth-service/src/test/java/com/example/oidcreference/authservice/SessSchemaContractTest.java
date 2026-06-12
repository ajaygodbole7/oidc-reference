package com.example.oidcreference.authservice;

import static org.assertj.core.api.Assertions.assertThat;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;

/**
 * SPEC-0001 §7.2: under the phantom-token split (§7.1) the Auth Service is the
 * sole reader and writer of sess:{sid} — the API Gateway holds no store handle
 * and never parses this key, so the schema is Auth-Service-private, not a
 * cross-component wire contract. This test pins the writer side: every field
 * listed in {@code required_fields_writer} of
 * {@code schema/sess-payload.example.json} must round-trip through
 * {@link SessionRecord}'s Jackson binding, and the payload itself must
 * deserialize into a SessionRecord with the documented field values.
 *
 * <p>A field rename or type change on the Java record will fail this test —
 * the fixture is intentionally separate from the SessionRecord source so a
 * refactor cannot silently rename a wire field on both sides at once.
 */
class SessSchemaContractTest {
  private static final Path FIXTURE_PATH = locateFixture();

  private final JsonMapper mapper = JsonMapper.builder().findAndAddModules().build();

  @Test
  void writerSerializesEveryRequiredField() throws Exception {
    JsonNode fixture = mapper.readTree(Files.readString(FIXTURE_PATH));
    List<String> requiredForWriter = mapper.convertValue(
        fixture.get("required_fields_writer"),
        mapper.constructType(List.class));

    SessionRecord record = mapper.treeToValue(fixture.get("payload"), SessionRecord.class);
    JsonNode reSerialized = mapper.valueToTree(record);

    for (String name : requiredForWriter) {
      assertThat(reSerialized.has(name))
          .as("SessionRecord must serialize required field: %s", name)
          .isTrue();
    }
  }

  @Test
  void payloadFieldValuesRoundTripExactly() throws Exception {
    JsonNode fixture = mapper.readTree(Files.readString(FIXTURE_PATH));
    JsonNode payload = fixture.get("payload");

    SessionRecord record = mapper.treeToValue(payload, SessionRecord.class);

    assertThat(record.accessToken()).isEqualTo(payload.get("access_token").asString());
    assertThat(record.refreshToken()).isEqualTo(payload.get("refresh_token").asString());
    assertThat(record.idToken()).isEqualTo(payload.get("id_token").asString());
    assertThat(record.expiresAt().toString()).isEqualTo(payload.get("access_token_expires_at").asString());
    assertThat(record.refreshExpiresAt().toString()).isEqualTo(payload.get("refresh_token_expires_at").asString());
    assertThat(record.createdAt().toString()).isEqualTo(payload.get("created_at").asString());
    assertThat(record.absoluteExpiresAt().toString()).isEqualTo(payload.get("absolute_expires_at").asString());
    @SuppressWarnings("unchecked")
    Map<String, Object> claims = mapper.convertValue(payload.get("claims"), Map.class);
    assertThat(record.claims()).containsEntry("sub", claims.get("sub"));
    assertThat(record.claims()).containsEntry("preferred_username", "alice");
  }

  @Test
  void readerOnlyRequiredFieldsAreSubsetOfWriterFields() throws Exception {
    // Catches the inverse drift: a writer field that the reader subset
    // forgot to list. If reader-required fields aren't writer-required,
    // the gateway will routinely 502.
    JsonNode fixture = mapper.readTree(Files.readString(FIXTURE_PATH));
    List<String> writerRequired = mapper.convertValue(
        fixture.get("required_fields_writer"),
        mapper.constructType(List.class));
    List<String> readerRequired = mapper.convertValue(
        fixture.get("required_fields_reader"),
        mapper.constructType(List.class));

    assertThat(writerRequired).containsAll(readerRequired);
  }

  private static Path locateFixture() {
    // Resolve repo-root/schema/sess-payload.example.json from the auth-service
    // module dir. Walks up one level — keeps the test working under both
    // `cd auth-service && ./mvnw test` and `./mvnw -pl auth-service test`.
    Path cwd = Path.of("").toAbsolutePath();
    Path candidate = cwd.resolve("schema/sess-payload.example.json");
    if (Files.exists(candidate)) {
      return candidate;
    }
    candidate = cwd.getParent().resolve("schema/sess-payload.example.json");
    if (Files.exists(candidate)) {
      return candidate;
    }
    throw new IllegalStateException(
        "Cannot find sess-payload.example.json relative to " + cwd);
  }
}
