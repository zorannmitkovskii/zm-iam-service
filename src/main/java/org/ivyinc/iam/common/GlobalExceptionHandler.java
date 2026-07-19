package org.ivyinc.iam.common;

import jakarta.validation.ConstraintViolationException;
import lombok.extern.slf4j.Slf4j;
import org.ivyinc.iam.common.exception.ApiError;
import org.ivyinc.iam.common.exception.BusinessException;
import org.ivyinc.iam.common.exception.DuplicateResourceException;
import org.ivyinc.iam.common.exception.ErrorCode;
import org.ivyinc.iam.common.exception.FieldError;
import org.ivyinc.iam.common.exception.ResourceNotFoundException;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.web.HttpMediaTypeNotSupportedException;
import org.springframework.web.HttpRequestMethodNotSupportedException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;

import java.time.LocalDateTime;
import java.util.List;

/**
 * Central error → {@link ApiResponse} translator. Trimmed-down version of the
 * ivy-events-be equivalent — IAM has no storage/upload exceptions to handle.
 * Extend with IAM-specific exceptions (e.g. ProvisioningConflictException) as
 * they're introduced.
 */
@Slf4j
@ControllerAdvice
public class GlobalExceptionHandler {

    // AuthN/AuthZ handlers land here once Spring Security is wired in IAM-05.
    // For now (no @EnableWebSecurity yet, no security starter on the classpath),
    // catching org.springframework.security.* exceptions would fail to compile.
    // Codes AUTHN_FAILED / AUTHZ_ACCESS_DENIED are already defined in ErrorCode
    // so the wiring will be a one-line change.

    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<ApiResponse<ApiError>> handleValidation(MethodArgumentNotValidException ex) {
        // Emit ONE entry per broken rule so clients can bind messages
        // back to form fields. Also aggregate a legacy `detail` string
        // for consumers that don't parse fieldErrors yet.
        List<FieldError> fieldErrors = ex.getBindingResult().getFieldErrors().stream()
                .map(fe -> new FieldError(fe.getField(), fe.getDefaultMessage()))
                .toList();
        String detail = fieldErrors.stream()
                .map(fe -> fe.field() + ": " + fe.message())
                .reduce((a, b) -> a + "; " + b)
                .orElse(ex.getMessage());
        return buildValidation(detail, fieldErrors);
    }

    @ExceptionHandler(ConstraintViolationException.class)
    public ResponseEntity<ApiResponse<ApiError>> handleConstraintViolation(ConstraintViolationException ex) {
        // Explode one entry per violation. Path is the property path from
        // the root object (e.g. "realms[1].clients[0].clientId") — same
        // shape MethodArgumentNotValidException gives, so clients handle
        // both uniformly.
        List<FieldError> fieldErrors = ex.getConstraintViolations().stream()
                .map(v -> new FieldError(v.getPropertyPath().toString(), v.getMessage()))
                .toList();
        String detail = fieldErrors.stream()
                .map(fe -> fe.field() + ": " + fe.message())
                .reduce((a, b) -> a + "; " + b)
                .orElse(ex.getMessage());
        return buildValidation(detail, fieldErrors);
    }

    /** Raised by ManifestParser when the body has a structural problem
     *  (unknown property, wrong type). Convert to 400 rather than
     *  bubbling to the 500 catch-all. */
    @ExceptionHandler(IllegalArgumentException.class)
    public ResponseEntity<ApiResponse<ApiError>> handleIllegalArgument(IllegalArgumentException ex) {
        return build(ErrorCode.MESSAGE_NOT_READABLE, "Malformed request body", ex.getMessage());
    }

    @ExceptionHandler(HttpMessageNotReadableException.class)
    public ResponseEntity<ApiResponse<ApiError>> handleUnreadable(HttpMessageNotReadableException ex) {
        return build(ErrorCode.MESSAGE_NOT_READABLE, "Malformed request body");
    }

    @ExceptionHandler(HttpRequestMethodNotSupportedException.class)
    public ResponseEntity<ApiResponse<ApiError>> handleMethodNotSupported(HttpRequestMethodNotSupportedException ex) {
        return build(ErrorCode.VALIDATION_ERROR, ex.getMessage());
    }

    @ExceptionHandler(HttpMediaTypeNotSupportedException.class)
    public ResponseEntity<ApiResponse<ApiError>> handleMediaType(HttpMediaTypeNotSupportedException ex) {
        return build(ErrorCode.VALIDATION_ERROR, ex.getMessage());
    }

    @ExceptionHandler(ResourceNotFoundException.class)
    public ResponseEntity<ApiResponse<ApiError>> handleNotFound(ResourceNotFoundException ex) {
        return build(ErrorCode.RESOURCE_NOT_FOUND, ex.getMessage());
    }

    @ExceptionHandler(DuplicateResourceException.class)
    public ResponseEntity<ApiResponse<ApiError>> handleDuplicate(DuplicateResourceException ex) {
        return build(ErrorCode.DUPLICATE_RESOURCE, ex.getMessage());
    }

    @ExceptionHandler(BusinessException.class)
    public ResponseEntity<ApiResponse<ApiError>> handleBusiness(BusinessException ex) {
        ErrorCode code = ex.getErrorCode() != null ? ex.getErrorCode() : ErrorCode.BUSINESS_ERROR;
        return build(code, ex.getMessage());
    }

    // Catch-all — log at ERROR so ops sees it; return generic message so we
    // don't leak internals to the client.
    @ExceptionHandler(Exception.class)
    public ResponseEntity<ApiResponse<ApiError>> handleUnexpected(Exception ex) {
        log.error("Unexpected error", ex);
        return build(ErrorCode.INTERNAL_SERVER_ERROR, "Unexpected internal error", ex.getMessage());
    }

    private ResponseEntity<ApiResponse<ApiError>> build(ErrorCode code, String message) {
        return build(code, message, null);
    }

    private ResponseEntity<ApiResponse<ApiError>> build(ErrorCode code, String message, String detail) {
        ApiError body = ApiError.builder()
                .status(code.status().value())
                .errorCode(code.code())
                .type("/problems/" + code.category().name().toLowerCase())
                .message(message)
                .detail(detail)
                .timestamp(LocalDateTime.now())
                .build();
        return ResponseEntity.status(code.status()).body(ApiResponse.error(message, body));
    }

    private ResponseEntity<ApiResponse<ApiError>> buildValidation(String detail, List<FieldError> fieldErrors) {
        ErrorCode code = ErrorCode.VALIDATION_ERROR;
        String message = "Validation failed";
        ApiError body = ApiError.builder()
                .status(code.status().value())
                .errorCode(code.code())
                .type("/problems/" + code.category().name().toLowerCase())
                .message(message)
                .detail(detail)
                .timestamp(LocalDateTime.now())
                .fieldErrors(fieldErrors)
                .build();
        return ResponseEntity.status(code.status()).body(ApiResponse.error(message, body));
    }
}
