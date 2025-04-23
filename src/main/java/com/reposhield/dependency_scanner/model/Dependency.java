package com.reposhield.dependency_scanner.model;

import jakarta.persistence.*;
import lombok.Data;

/**
 * Represents a dependency found in a repository.
 */
@Data
@Entity
public class Dependency {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private String name;
    private String groupId;
    private String artifactId;
    private String version;

    @ManyToOne
    private Repository repository;
}