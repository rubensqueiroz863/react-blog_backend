# Use uma imagem oficial do Java como base
FROM eclipse-temurin:17-jdk-alpine

# Diretório de trabalho dentro do container
WORKDIR /app

# Copia todos os arquivos do projeto
COPY . .

# Dá permissão de execução ao Maven Wrapper
RUN chmod +x mvnw

# Build do projeto usando Maven Wrapper
RUN ./mvnw clean package -DskipTests

# Expõe a porta que o Spring Boot vai usar
EXPOSE 8080

# Comando para rodar a aplicação
CMD ["java", "-jar", "target/backend-0.0.1-SNAPSHOT.jar"]
