# Etapa 1: build
FROM eclipse-temurin:17-jdk-alpine AS builder
WORKDIR /app
COPY . .

# dá permissão para o mvnw
RUN chmod +x mvnw

RUN ./mvnw clean package -DskipTests
