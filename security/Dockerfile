# Use an official OpenJDK runtime as a parent image
FROM openjdk:21-jdk-slim

# Set the working directory
WORKDIR /app

# Add the application's JAR file to the container
COPY target/*.jar /app/app.jar

# Run the JAR file
ENTRYPOINT ["java", "-jar", "/app/app.jar"]
