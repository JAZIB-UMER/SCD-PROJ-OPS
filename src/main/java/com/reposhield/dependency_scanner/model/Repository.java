package com.reposhield.dependency_scanner.model;

import jakarta.persistence.*;
import lombok.Data;
import java.time.LocalDateTime;

/**
 * Represents a GitHub repository to be scanned.
 */
@Data
@Entity
public class Repository {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private String name;
    private String url;
    private String owner;

    private LocalDateTime lastScanned;
}