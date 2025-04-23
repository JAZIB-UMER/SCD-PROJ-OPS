package com.reposhield.dependency_scanner.service;

import com.reposhield.dependency_scanner.model.Dependency;
import com.reposhield.dependency_scanner.model.Repository;
import com.reposhield.dependency_scanner.model.ScanResult;
import com.reposhield.dependency_scanner.model.Vulnerability;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.io.FileNotFoundException;
import java.time.LocalDateTime;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.stream.Collectors;

/**
 * Main service for coordinating repository scans.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class ScanService {

    private final GitHubService gitHubService;
    private final DependencyParser dependencyParser;
    private final VulnerabilityService vulnerabilityService;

    /**
     * Performs a complete scan of a repository.
     */
    public ScanResult scanRepository(Repository repository) {
        log.info("Starting scan for repository: {}/{}", repository.getOwner(), repository.getName());

        ScanResult scanResult = new ScanResult();
        scanResult.setRepository(repository);
        scanResult.setScanDate(LocalDateTime.now());
        scanResult.setScanStatus("IN_PROGRESS");

        try {
            // Add a timeout for the entire scan operation
            CompletableFuture<Void> future = CompletableFuture.runAsync(() -> {
                try {
                    // 1. Fetch the pom.xml content
                    String pomXmlContent = gitHubService.getPomXmlContent(
                            repository.getOwner(), repository.getName());

                    // 2. Parse the dependencies
                    List<Dependency> dependencies = dependencyParser.parsePomXml(pomXmlContent, repository);
                    scanResult.setDependencies(dependencies);
                    scanResult.setTotalDependencies(dependencies.size());

                    // 3. Scan dependencies for vulnerabilities
                    List<Vulnerability> vulnerabilities = vulnerabilityService.scanDependencies(dependencies);
                    scanResult.setVulnerabilities(vulnerabilities);

                    // 4. Count vulnerable dependencies
                    long vulnerableDepsCount = dependencies.stream()
                            .filter(dep -> vulnerabilities.stream()
                                    .anyMatch(vuln -> vuln.getDependencyName().equals(dep.getName())))
                            .count();
                    scanResult.setVulnerableDependencies((int) vulnerableDepsCount);

                    // 5. Update repository lastScanned timestamp
                    repository.setLastScanned(LocalDateTime.now());

                    scanResult.setScanStatus("COMPLETE");
                    log.info("Scan completed successfully");
                } catch (Exception e) {
                    log.error("Error during scan: {}", e.getMessage(), e);
                    scanResult.setScanStatus("FAILED");
                }
            });

            // Wait for the scan to complete with a timeout
            try {
                future.get(30, TimeUnit.SECONDS);
            } catch (TimeoutException e) {
                log.error("Scan timed out after 30 seconds");
                scanResult.setScanStatus("FAILED");
                throw new RuntimeException("Scan timed out");
            } catch (Exception e) {
                log.error("Error waiting for scan to complete: {}", e.getMessage());
                scanResult.setScanStatus("FAILED");
                throw e;
            }

        } catch (Exception e) {
            log.error("Scan failed: {}", e.getMessage(), e);
            scanResult.setScanStatus("FAILED");
        }

        return scanResult;
    }

    /**
     * Returns a summary of scan results.
     */
    public String getScanSummary(ScanResult scanResult) {
        StringBuilder summary = new StringBuilder();

        summary.append("Scan Summary for ").append(scanResult.getRepository().getOwner())
                .append("/").append(scanResult.getRepository().getName()).append("\n");
        summary.append("Scan Date: ").append(scanResult.getScanDate()).append("\n");
        summary.append("Status: ").append(scanResult.getScanStatus()).append("\n");
        summary.append("Total Dependencies: ").append(scanResult.getTotalDependencies()).append("\n");
        summary.append("Vulnerable Dependencies: ").append(scanResult.getVulnerableDependencies()).append("\n");

        if (!scanResult.getVulnerabilities().isEmpty()) {
            summary.append("\nVulnerabilities:\n");

            List<Vulnerability> criticalVulns = scanResult.getVulnerabilities().stream()
                    .filter(v -> "CRITICAL".equals(v.getSeverity()))
                    .collect(Collectors.toList());

            List<Vulnerability> highVulns = scanResult.getVulnerabilities().stream()
                    .filter(v -> "HIGH".equals(v.getSeverity()))
                    .collect(Collectors.toList());

            summary.append("Critical: ").append(criticalVulns.size()).append("\n");
            summary.append("High: ").append(highVulns.size()).append("\n");
            summary.append("Other: ").append(scanResult.getVulnerabilities().size() -
                    criticalVulns.size() - highVulns.size()).append("\n");

            if (!criticalVulns.isEmpty()) {
                summary.append("\nCritical Vulnerabilities:\n");
                criticalVulns.forEach(v -> {
                    summary.append(" - ").append(v.getCveId()).append(": ")
                            .append(v.getDependencyName()).append(" (")
                            .append(v.getAffectedVersion()).append(")\n");
                });
            }
        }

        return summary.toString();
    }
}