package com.reposhield.dependency_scanner.service;

import com.reposhield.dependency_scanner.model.Dependency;
import com.reposhield.dependency_scanner.model.Repository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for the DependencyParser.
 */
public class DependencyParserTests {

    private DependencyParser dependencyParser;
    private Repository testRepository;

    @BeforeEach
    public void setup() {
        dependencyParser = new DependencyParser();
        testRepository = new Repository();
        testRepository.setId(1L);
        testRepository.setName("test-repo");
        testRepository.setOwner("test-owner");
    }

    @Test
    public void testParsePomXml() {
        // Sample pom.xml content
        String pomXml = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n" +
                "<project xmlns=\"http://maven.apache.org/POM/4.0.0\"\n" +
                "         xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\"\n" +
                "         xsi:schemaLocation=\"http://maven.apache.org/POM/4.0.0 http://maven.apache.org/xsd/maven-4.0.0.xsd\">\n" +
                "    <modelVersion>4.0.0</modelVersion>\n" +
                "    <groupId>com.example</groupId>\n" +
                "    <artifactId>sample-project</artifactId>\n" +
                "    <version>1.0.0</version>\n" +
                "    <dependencies>\n" +
                "        <dependency>\n" +
                "            <groupId>org.springframework.boot</groupId>\n" +
                "            <artifactId>spring-boot-starter-web</artifactId>\n" +
                "            <version>2.7.0</version>\n" +
                "        </dependency>\n" +
                "        <dependency>\n" +
                "            <groupId>org.apache.logging.log4j</groupId>\n" +
                "            <artifactId>log4j-core</artifactId>\n" +
                "            <version>2.14.1</version>\n" +
                "        </dependency>\n" +
                "    </dependencies>\n" +
                "</project>";

        // Parse the pom.xml
        List<Dependency> dependencies = dependencyParser.parsePomXml(pomXml, testRepository);

        // Verify results
        assertEquals(2, dependencies.size());

        Dependency springBootDep = dependencies.get(0);
        assertEquals("org.springframework.boot", springBootDep.getGroupId());
        assertEquals("spring-boot-starter-web", springBootDep.getArtifactId());
        assertEquals("2.7.0", springBootDep.getVersion());

        Dependency log4jDep = dependencies.get(1);
        assertEquals("org.apache.logging.log4j", log4jDep.getGroupId());
        assertEquals("log4j-core", log4jDep.getArtifactId());
        assertEquals("2.14.1", log4jDep.getVersion());
    }

    @Test
    public void testParsePomXml_InvalidContent() {
        // Invalid XML content
        String invalidPomXml = "This is not valid XML content";

        // Verify that an exception is thrown
        assertThrows(RuntimeException.class, () -> {
            dependencyParser.parsePomXml(invalidPomXml, testRepository);
        });
    }
}