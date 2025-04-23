package com.reposhield.dependency_scanner.model;

import jakarta.persistence.*;
import lombok.Data;
import java.time.LocalDateTime;
import java.util.List;
import java.util.ArrayList;

/**
 * Represents the result of a repository scan.
 */
@Data
@Entity
public class ScanResult {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne
    private Repository repository;

    private LocalDateTime scanDate;

    @OneToMany(cascade = CascadeType.ALL)
    private List<Dependency> dependencies = new ArrayList<>();

    @OneToMany(cascade = CascadeType.ALL)
    private List<Vulnerability> vulnerabilities = new ArrayList<>();

    private int totalDependencies;
    private int vulnerableDependencies;

    private String scanStatus; // "COMPLETE", "IN_PROGRESS", "FAILED"
}