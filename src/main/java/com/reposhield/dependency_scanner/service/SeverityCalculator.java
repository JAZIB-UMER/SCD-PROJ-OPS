package com.reposhield.dependency_scanner.service;

import com.reposhield.dependency_scanner.model.Vulnerability;
import org.springframework.stereotype.Service;

/**
 * Service for calculating and normalizing severity levels of vulnerabilities.
 */
@Service
public class SeverityCalculator {

    /**
     * Calculates numerical severity score based on severity level.
     * This is a simplified implementation.
     */
    public int calculateSeverityScore(Vulnerability vulnerability) {
        String severity = vulnerability.getSeverity();
        if (severity == null) {
            return 0;
        }

        return switch (severity.toUpperCase()) {
            case "CRITICAL" -> 5;
            case "HIGH" -> 4;
            case "MEDIUM" -> 3;
            case "LOW" -> 2;
            case "INFO" -> 1;
            default -> 0;
        };
    }

    /**
     * Normalizes different severity formats to a standard format.
     */
    public String normalizeSeverity(String severity) {
        if (severity == null) {
            return "UNKNOWN";
        }

        severity = severity.toUpperCase();

        // Convert numeric scores to text
        if (severity.matches("\\d+(\\.\\d+)?")) {
            double score = Double.parseDouble(severity);
            if (score >= 9.0) return "CRITICAL";
            if (score >= 7.0) return "HIGH";
            if (score >= 4.0) return "MEDIUM";
            if (score > 0.0) return "LOW";
            return "INFO";
        }

        // Normalize text values
        if (severity.contains("CRITICAL") || severity.contains("SEVERE")) {
            return "CRITICAL";
        } else if (severity.contains("HIGH") || severity.contains("IMPORTANT")) {
            return "HIGH";
        } else if (severity.contains("MEDIUM") || severity.contains("MODERATE")) {
            return "MEDIUM";
        } else if (severity.contains("LOW") || severity.contains("MINOR")) {
            return "LOW";
        } else if (severity.contains("INFO") || severity.contains("NONE")) {
            return "INFO";
        }

        return "UNKNOWN";
    }
}