# Backend Resource Server

Java 25 and Spring Boot resource server for the OIDC reference project.

This directory owns API endpoints, Spring Security OAuth2 Resource Server
configuration, JWT validation, scope/role mapping, CORS enforcement, and backend
tests.

## Required Commands

```bash
./mvnw test
./mvnw spring-boot:run
../scripts/verify-backend.sh
```

## Configuration

```bash
OIDC_ISSUER_URI=http://localhost:8080/realms/oidc-reference
OIDC_AUDIENCE=oidc-reference-api
SERVER_PORT=8082
```

The Resource Server is not called directly by the browser. Browser CORS is
denied in code; the BFF is the only browser-facing API surface.

## Harness Requirements

- Maven wrapper exists.
- `pom.xml` targets Java 25 and Spring Boot 4.
- Tests cover public endpoint access and missing-token rejection first.
- Endpoint-to-authority mapping is documented before admin/service endpoints are
  implemented.
- `../scripts/verify-backend.sh` runs backend tests.
