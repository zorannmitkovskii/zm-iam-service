package org.ivyinc.iam.common.exception;

import lombok.Builder;

import java.time.LocalDateTime;

/**
 * Body payload for HTTP error responses. Wrapped inside
 * {@link org.ivyinc.iam.common.ApiResponse}{@code .data} by the exception handler.
 */
@Builder
public record ApiError(
        int status,
        String errorCode,
        String type,
        String message,
        String detail,
        LocalDateTime timestamp
) {}
