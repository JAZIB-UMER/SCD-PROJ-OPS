package com.reposhield.dependency_scanner.service;

import com.reposhield.dependency_scanner.model.Dependency;
import com.reposhield.dependency_scanner.model.Repository;
import lombok.extern.slf4j.Slf4j;
import org.apache.maven.model.Model;
import org.apache.maven.model.io.xpp3.MavenXpp3Reader;
import org.codehaus.plexus.util.xml.pull.XmlPullParserException;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.io.StringReader;
import java.util.ArrayList;
import java.util.List;

/**
 * Service for parsing dependency files (currently only Maven pom.xml).
 */
@Slf4j
@Service
public class DependencyParser {

    /**
     * Parses Maven pom.xml file content and extracts dependencies.
     */
    public List<Dependency> parsePomXml(String pomXmlContent, Repository repository) {
        List<Dependency> dependencies = new ArrayList<>();

        try {
            MavenXpp3Reader reader = new MavenXpp3Reader();
            Model model = reader.read(new StringReader(pomXmlContent));

            for (org.apache.maven.model.Dependency mavenDep : model.getDependencies()) {
                Dependency dependency = new Dependency();
                dependency.setGroupId(mavenDep.getGroupId());
                dependency.setArtifactId(mavenDep.getArtifactId());
                dependency.setVersion(mavenDep.getVersion());
                dependency.setName(mavenDep.getGroupId() + ":" + mavenDep.getArtifactId());
                dependency.setRepository(repository);

                dependencies.add(dependency);
                log.debug("Found dependency: {}:{}:{}",
                        mavenDep.getGroupId(), mavenDep.getArtifactId(), mavenDep.getVersion());
            }

            log.info("Extracted {} dependencies from pom.xml", dependencies.size());
            return dependencies;

        } catch (IOException | XmlPullParserException e) {
            log.error("Error parsing pom.xml: {}", e.getMessage());
            throw new RuntimeException("Error parsing pom.xml: " + e.getMessage(), e);
        }
    }
}