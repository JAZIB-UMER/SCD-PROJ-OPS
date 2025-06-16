# Stage 1: Build with Maven + JDK
FROM maven:3.9.6-eclipse-temurin-21 as builder

WORKDIR /app
COPY . .
RUN mvn clean package -DskipTests

# Stage 2: Minimal runtime using Distroless Java 21
FROM gcr.io/distroless/java21

WORKDIR /app
COPY --from=builder /app/target/*.jar /app/app.jar

# Document the exposed port (optional but recommended)
EXPOSE 8081

# Distroless expects a Java entrypoint
CMD ["app.jar"]
