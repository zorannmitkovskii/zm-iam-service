package zm.iam.common.exception;

/**
 * Domain-rule violation raised by services (e.g. "manifest version already
 * applied", "service is not the owner of this realm"). Handled by
 * {@link zm.iam.common.GlobalExceptionHandler} as 422.
 */
public class BusinessException extends RuntimeException {

    private final ErrorCode errorCode;

    public BusinessException(String message) {
        this(ErrorCode.BUSINESS_ERROR, message);
    }

    public BusinessException(ErrorCode errorCode, String message) {
        super(message);
        this.errorCode = errorCode;
    }

    public ErrorCode getErrorCode() {
        return errorCode;
    }
}
