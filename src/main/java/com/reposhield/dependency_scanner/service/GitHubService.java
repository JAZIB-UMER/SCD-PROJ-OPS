package com.reposhield.dependency_scanner.service;

import com.reposhield.dependency_scanner.model.Repository;
import lombok.extern.slf4j.Slf4j;
import org.kohsuke.github.*;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.util.Base64;

/**
 * Service for interacting with the GitHub API.
 */
@Slf4j
@Service
public class GitHubService {
    private final GitHub gitHub;

    /**
     * Constructor that initializes GitHub API connection.
     * Uses anonymous connection for simplicity, but can be configured to use OAuth token.
     */
    public GitHubService(@Value("${github.token:}") String token) throws IOException {
        if (token != null && !token.isEmpty()) {
            this.gitHub = new GitHubBuilder().withOAuthToken(token).build();
            log.info("Connected to GitHub with authentication");
        } else {
            this.gitHub = GitHub.connectAnonymously();
            log.info("Connected to GitHub anonymously");
        }
    }

    /**
     * Retrieves repository details from GitHub.
     */
    public Repository getRepositoryDetails(String owner, String repoName) {
        try {
            GHRepository ghRepo = gitHub.getRepository(owner + "/" + repoName);
            Repository repo = new Repository();
            repo.setName(ghRepo.getName());
            repo.setOwner(ghRepo.getOwnerName());
            repo.setUrl(ghRepo.getHtmlUrl().toString());
            return repo;
        } catch (IOException e) {
            log.error("Error fetching repository: {}", e.getMessage());
            throw new RuntimeException("Error fetching repository: " + e.getMessage(), e);
        }
    }

    /**
     * Fetches the content of pom.xml from the repository.
     * Currently only supports Maven projects.
     */
    public String getPomXmlContent(String owner, String repoName) {
        try {
            log.info("Fetching pom.xml from {}/{}", owner, repoName);
            GHRepository repository = gitHub.getRepository(owner + "/" + repoName);

            // Set a timeout for fetching content
            int timeoutMillis = 10000; // 10 seconds
            GHContent content = repository.getFileContent("pom.xml");

            if (content != null && content.isFile()) {
                try {
                    String rawContent = content.getContent();
                    log.info("Successfully fetched pom.xml content");
                    return rawContent;
                } catch (Exception e) {
                    log.error("Error decoding pom.xml content: {}", e.getMessage());
                    throw new RuntimeException("Error processing pom.xml content", e);
                }
            } else {
                log.error("pom.xml not found or is not a file");
                throw new RuntimeException("pom.xml not found or is not a file");
            }
        } catch (Exception e) {
            log.error("Error fetching pom.xml: {}", e.getMessage(), e);
            throw new RuntimeException("Error fetching pom.xml: " + e.getMessage(), e);
        }
    }
}