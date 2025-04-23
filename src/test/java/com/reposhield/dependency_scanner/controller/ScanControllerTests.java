package com.reposhield.dependency_scanner.controller;

import com.reposhield.dependency_scanner.model.Repository;
import com.reposhield.dependency_scanner.model.ScanResult;
import com.reposhield.dependency_scanner.service.GitHubService;
import com.reposhield.dependency_scanner.service.ScanService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.test.web.servlet.MockMvc;

import java.time.LocalDateTime;

import static org.mockito.ArgumentMatchers.any;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Tests for the ScanController.
 */
@WebMvcTest(ScanController.class)
public class ScanControllerTests {

    @Autowired
    private MockMvc mockMvc;

    @MockBean
    private GitHubService gitHubService;

    @MockBean
    private ScanService scanService;

    private Repository testRepository;
    private ScanResult testScanResult;

    @BeforeEach
    public void setup() {
        // Set up test data
        testRepository = new Repository();
        testRepository.setId(1L);
        testRepository.setName("test-repo");
        testRepository.setOwner("test-owner");
        testRepository.setUrl("https://github.com/test-owner/test-repo");

        testScanResult = new ScanResult();
        testScanResult.setId(1L);
        testScanResult.setRepository(testRepository);
        testScanResult.setScanDate(LocalDateTime.now());
        testScanResult.setScanStatus("COMPLETE");
        testScanResult.setTotalDependencies(5);
        testScanResult.setVulnerableDependencies(2);
    }

    @Test
    public void testHealthEndpoint() throws Exception {
        mockMvc.perform(get("/api/health"))
                .andExpect(status().isOk())
                .andExpect(content().string("RepoShield Guardian is running"));
    }

    @Test
    public void testScanRepository() throws Exception {
        // Mock service responses
        Mockito.when(gitHubService.getRepositoryDetails("test-owner", "test-repo"))
                .thenReturn(testRepository);
        Mockito.when(scanService.scanRepository(any(Repository.class)))
                .thenReturn(testScanResult);

        // Perform the request and verify
        mockMvc.perform(post("/api/scan")
                        .param("owner", "test-owner")
                        .param("repo", "test-repo"))
                .andExpect(status().isOk());
    }
}