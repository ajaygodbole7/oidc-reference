# syntax=docker/dockerfile:1.7
#
# OIDC Reference — Auth Service
#
# Confidential OIDC token issuer for local development. Public HTTP on 8081,
# Spring Boot Actuator on 9081. Java 25 + Spring Boot 4.1.0, virtual
# threads enabled by the application. Multi-stage build; runtime image is a
# JRE-only layer with a non-root user and curl present so Compose can run
# its healthcheck against /actuator/health.
#
# Base image note: we pin eclipse-temurin:25-jdk-jammy / 25-jre-jammy.
# An alpine 25 JRE tag is not consistently published yet, so jammy is the
# safe, reproducible choice (glibc + apt for installing curl).

# ── Build stage ───────────────────────────────────────────────────────────
FROM eclipse-temurin:25-jdk-jammy AS build

# The repo's mvnw is a minimal `exec mvn "$@"` shim, NOT the full Maven
# Wrapper, so we need a real Maven on PATH in the build stage. The
# project's enforcer requires Maven [3.9.6,) which ubuntu jammy's apt
# package (3.6.3) does not satisfy, so install the upstream binary.
ARG MAVEN_VERSION=3.9.11
RUN apt-get update && apt-get install -y --no-install-recommends curl ca-certificates && \
    curl -fsSL "https://archive.apache.org/dist/maven/maven-3/${MAVEN_VERSION}/binaries/apache-maven-${MAVEN_VERSION}-bin.tar.gz" \
      | tar -xz -C /opt && \
    ln -s /opt/apache-maven-${MAVEN_VERSION}/bin/mvn /usr/local/bin/mvn && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /workspace

# Copy pom + mvnw first so Maven can warm its dep cache before sources land.
# No .mvn/ in this repo — mvnw here is just `exec mvn "$@"` and the real
# Maven is installed above, so the wrapper directory isn't needed.
COPY pom.xml mvnw ./
RUN chmod +x mvnw && mvn -B -q -DskipTests dependency:go-offline || true

# Now copy sources and package.
COPY src src
RUN ./mvnw -B -q -DskipTests package

# Boot 4's `Djarmode=tools extract --layers` directory layout differs
# from Boot 3.x's `layertools`, and a reference repo doesn't need the
# layer-caching benefit. COPY the fat jar directly — simpler, fewer
# moving parts.

# ── Runtime stage ─────────────────────────────────────────────────────────
FROM eclipse-temurin:25-jre-jammy

# curl is required by the Compose healthcheck. Drop apt lists to keep the
# image lean. Create a dedicated non-root user up-front.
RUN apt-get update && apt-get install -y --no-install-recommends curl && \
    rm -rf /var/lib/apt/lists/* && \
    groupadd --system spring && useradd --system --gid spring spring

USER spring:spring
WORKDIR /app

COPY --from=build --chown=spring:spring /workspace/target/*-SNAPSHOT.jar /app/app.jar

# Document the public + management ports. EXPOSE is informational only —
# Compose publishes the actual host bindings.
EXPOSE 8081 9081

ENTRYPOINT ["java", \
  "-XX:MaxRAMPercentage=75.0", \
  "-XX:+UseG1GC", \
  "-XX:+ExitOnOutOfMemoryError", \
  "-Djava.security.egd=file:/dev/./urandom", \
  "-jar", "/app/app.jar"]
