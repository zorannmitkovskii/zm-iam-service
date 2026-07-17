package org.ivyinc.iam.common;

import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Standard response envelope for all IAM HTTP responses. Mirrors the
 * {@code ivy-events-be} shape so consumers can reuse existing client code.
 */
@Data
@Builder
@NoArgsConstructor
public class ApiResponse<T> {
    private boolean success;
    private String message;
    private T data;

    public ApiResponse(boolean success, String message, T data) {
        this.success = success;
        this.message = message;
        this.data = data;
    }

    public static <T> ApiResponse<T> ok(T data) {
        return new ApiResponse<>(true, null, data);
    }

    public static <T> ApiResponse<T> fail(String message) {
        return new ApiResponse<>(false, message, null);
    }

    public static <T> ApiResponse<T> error(String message, T data) {
        return new ApiResponse<>(false, message, data);
    }
}
