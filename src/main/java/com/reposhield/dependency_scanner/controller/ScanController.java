package com.reposhield.dependency_scanner.controller;

import com.reposhield.dependency_scanner.exception.PomFileNotFoundException;
import com.reposhield.dependency_scanner.model.Repository;
import com.reposhield.dependency_scanner.model.ScanResult;
import com.reposhield.dependency_scanner.service.GitHubService;
import com.reposhield.dependency_scanner.service.ScanService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.Map;

/**
 * REST controller for scanning repositories and retrieving scan results.
 */
@Slf4j
@RestController
@RequestMapping("/api")
@RequiredArgsConstructor
@CrossOrigin(origins = "*")
public class ScanController {
    private final GitHubService gitHubService;
    private final ScanService scanService;

    /**
     * Request class for scan requests with JSON body
     */
    public static class ScanRequest {
        private String owner;
        private String repo;

        // Getters and setters
        public String getOwner() {
            return owner;
        }

        public void setOwner(String owner) {
            this.owner = owner;
        }

        public String getRepo() {
            return repo;
        }

        public void setRepo(String repo) {
            this.repo = repo;
        }
    }

    /**
     * Initiates a new repository scan.
     * Accepts a JSON body with owner and repo fields.
     */
    @PostMapping("/scan")
    public ResponseEntity<ScanResult> scanRepository(@RequestBody ScanRequest request) {
        log.info("Scan request received for {}/{}", request.getOwner(), request.getRepo());
        try {
            Repository repository = gitHubService.getRepositoryDetails(request.getOwner(), request.getRepo());
            ScanResult result = scanService.scanRepository(repository);
            return ResponseEntity.ok(result);
        } catch (PomFileNotFoundException e) {
            log.info("POM file not found for {}/{}: {}", request.getOwner(), request.getRepo(), e.getMessage());
            // Return a clean error that will be handled by the frontend
            throw e;
        } catch (Exception e) {
            log.error("Error scanning repository {}/{}: {}", request.getOwner(), request.getRepo(), e.getMessage());
            throw e;
        }
    }

    /**
     * Exception handler for PomFileNotFoundException
     */
    @ExceptionHandler(PomFileNotFoundException.class)
    public ResponseEntity<Map<String, String>> handlePomFileNotFoundException(PomFileNotFoundException ex) {
        Map<String, String> response = new HashMap<>();
        response.put("message", "pom.xml not found in repository. Only Maven projects are supported.");
        response.put("status", "NOT_FOUND");

        // Log at INFO level instead of ERROR since this is an expected condition
        log.info("POM file not found: {}", ex.getMessage());

        return new ResponseEntity<>(response, HttpStatus.NOT_FOUND);
    }

    /**
     * Health check endpoint.
     */
    @GetMapping("/health")
    public ResponseEntity<String> health() {
        return ResponseEntity.ok("RepoShield Guardian is running");
    }
}