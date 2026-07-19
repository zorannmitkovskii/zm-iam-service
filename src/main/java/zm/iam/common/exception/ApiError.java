package zm.iam.common.exception;

import lombok.Builder;

import java.time.LocalDateTime;
import java.util.List;

/**
 * Body payload for HTTP error responses. Wrapped inside
 * {@link zm.iam.common.ApiResponse}{@code .data} by the exception handler.
 *
 * <p>{@code fieldErrors} is populated ONLY for validation failures
 * (400 Bad Request from Bean Validation). Other error codes leave it null.
 */
@Builder
public record ApiError(
        int status,
        String errorCode,
        String type,
        String message,
        String detail,
        LocalDateTime timestamp,
        List<FieldError> fieldErrors
) {}
