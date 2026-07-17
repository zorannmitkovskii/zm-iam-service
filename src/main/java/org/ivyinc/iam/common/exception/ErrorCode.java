package org.ivyinc.iam.common.exception;

import org.springframework.http.HttpStatus;

/**
 * Enumeration of all API-visible error codes for IAM. Each code carries
 * category, HTTP status, and a stable machine-readable identifier so
 * clients can branch on {@code errorCode} regardless of the human-readable
 * message.
 */
public enum ErrorCode {

    // Authentication
    AUTHN_FAILED           (ErrorCategory.AUTHENTICATION, HttpStatus.UNAUTHORIZED, "AUTHN_FAILED"),
    AUTHN_TOKEN_INVALID    (ErrorCategory.AUTHENTICATION, HttpStatus.UNAUTHORIZED, "AUTHN_TOKEN_INVALID"),

    // Authorization
    AUTHZ_ACCESS_DENIED    (ErrorCategory.AUTHORIZATION, HttpStatus.FORBIDDEN,   "AUTHZ_ACCESS_DENIED"),

    // Validation
    VALIDATION_ERROR       (ErrorCategory.VALIDATION,    HttpStatus.BAD_REQUEST, "VALIDATION_ERROR"),
    CONSTRAINT_VIOLATION   (ErrorCategory.VALIDATION,    HttpStatus.BAD_REQUEST, "CONSTRAINT_VIOLATION"),
    MESSAGE_NOT_READABLE   (ErrorCategory.VALIDATION,    HttpStatus.BAD_REQUEST, "MESSAGE_NOT_READABLE"),

    // Not found / conflict
    RESOURCE_NOT_FOUND     (ErrorCategory.NOT_FOUND,     HttpStatus.NOT_FOUND,   "RESOURCE_NOT_FOUND"),
    DUPLICATE_RESOURCE     (ErrorCategory.CONFLICT,      HttpStatus.CONFLICT,    "DUPLICATE_RESOURCE"),

    // Business
    BUSINESS_ERROR         (ErrorCategory.BUSINESS,      HttpStatus.UNPROCESSABLE_ENTITY, "BUSINESS_ERROR"),

    // Rate limiting
    RATE_LIMITED           (ErrorCategory.RATE_LIMIT,    HttpStatus.TOO_MANY_REQUESTS,    "RATE_LIMITED"),

    // Fallback
    INTERNAL_SERVER_ERROR  (ErrorCategory.INTERNAL,      HttpStatus.INTERNAL_SERVER_ERROR, "INTERNAL_SERVER_ERROR");

    private final ErrorCategory category;
    private final HttpStatus status;
    private final String code;

    ErrorCode(ErrorCategory category, HttpStatus status, String code) {
        this.category = category;
        this.status = status;
        this.code = code;
    }

    public ErrorCategory category() { return category; }
    public HttpStatus status()      { return status; }
    public String code()            { return code; }
}
