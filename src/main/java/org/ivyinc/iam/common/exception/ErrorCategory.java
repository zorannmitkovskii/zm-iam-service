package org.ivyinc.iam.common.exception;

/**
 * Coarse classification of {@link ErrorCode}s so the exception handler can
 * decide status codes and log levels consistently.
 */
public enum ErrorCategory {
    AUTHENTICATION,
    AUTHORIZATION,
    VALIDATION,
    NOT_FOUND,
    CONFLICT,
    BUSINESS,
    RATE_LIMIT,
    INTERNAL
}
