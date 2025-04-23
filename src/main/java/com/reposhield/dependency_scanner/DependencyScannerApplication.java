package com.reposhield.dependency_scanner;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * Main entry point for the RepoShield Guardian application.
 * This application scans GitHub repositories for vulnerable dependencies.
 */
@SpringBootApplication
public class DependencyScannerApplication {
	public static void main(String[] args) {
		SpringApplication.run(DependencyScannerApplication.class, args);
	}
}