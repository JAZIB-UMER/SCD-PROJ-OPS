package com.reposhield.dependency_scanner.exception;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

/**
 * Exception thrown when a pom.xml file is not found in the repository.
 */
@ResponseStatus(HttpStatus.NOT_FOUND)
public class PomFileNotFoundException extends RuntimeException {

    public PomFileNotFoundException(String message) {
        super(message);
    }

    public PomFileNotFoundException(String message, Throwable cause) {
        super(message, cause);
    }
}