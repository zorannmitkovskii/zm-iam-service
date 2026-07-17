# Multi-stage build for zm-iam-service.
# Stage 1: Maven builds the fat jar.
# Stage 2: minimal JRE image runs it.

FROM maven:3.9-eclipse-temurin-21 AS builder
WORKDIR /workspace

# Copy pom first for better layer caching — dependencies re-resolve only when
# pom.xml changes, not on every source edit.
COPY pom.xml .
RUN mvn -B -q dependency:go-offline

COPY src ./src
RUN mvn -B -q package -DskipTests

# ─────────────────────────────────────────────────────────────

FROM eclipse-temurin:21-jre-alpine
WORKDIR /app

# curl is used by the Docker HEALTHCHECK below.
RUN apk add --no-cache curl

COPY --from=builder /workspace/target/*.jar /app/app.jar

EXPOSE 8383

# Container healthcheck: hits Spring Boot Actuator's liveness probe. Non-200
# → docker marks the container as unhealthy → compose/orchestrator can act.
HEALTHCHECK --interval=15s --timeout=3s --start-period=45s --retries=5 \
  CMD curl -fsS http://localhost:8383/actuator/health/liveness || exit 1

ENTRYPOINT ["java", "-jar", "app.jar"]
