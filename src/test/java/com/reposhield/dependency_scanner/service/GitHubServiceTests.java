package com.reposhield.dependency_scanner.service;

import com.reposhield.dependency_scanner.model.Repository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.kohsuke.github.GHRepository;
import org.kohsuke.github.GitHub;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.test.util.ReflectionTestUtils;

import java.io.IOException;
import java.net.URL;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.when;

/**
 * Tests for the GitHubService.
 */
@ExtendWith(MockitoExtension.class)
public class GitHubServiceTests {

    @Mock
    private GitHub gitHub;

    @Mock
    private GHRepository ghRepository;

    private GitHubService gitHubService;

    @BeforeEach
    public void setup() throws IOException {
        gitHubService = new GitHubService("");
        ReflectionTestUtils.setField(gitHubService, "gitHub", gitHub);
    }

    @Test
    public void testGetRepositoryDetails() throws IOException {
        // Set up mock responses
        when(gitHub.getRepository("owner/repo")).thenReturn(ghRepository);
        when(ghRepository.getName()).thenReturn("repo");
        when(ghRepository.getOwnerName()).thenReturn("owner");
        when(ghRepository.getHtmlUrl()).thenReturn(new URL("https://github.com/owner/repo"));

        // Call the service method
        Repository repository = gitHubService.getRepositoryDetails("owner", "repo");

        // Verify results
        assertEquals("repo", repository.getName());
        assertEquals("owner", repository.getOwner());
        assertEquals("https://github.com/owner/repo", repository.getUrl());
    }

    @Test
    public void testGetRepositoryDetails_Error() throws IOException {
        // Setup mock to throw an exception
        when(gitHub.getRepository("owner/repo")).thenThrow(new IOException("Repository not found"));

        // Verify that the service method throws a RuntimeException
        RuntimeException exception = assertThrows(RuntimeException.class, () -> {
            gitHubService.getRepositoryDetails("owner", "repo");
        });

        assertEquals("Error fetching repository: Repository not found", exception.getMessage());
    }
}