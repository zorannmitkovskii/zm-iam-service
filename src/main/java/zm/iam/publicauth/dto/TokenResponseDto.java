package zm.iam.publicauth.dto;

/**
 * Response of login + verify-email. Field names match ivy-events-be's
 * current login response so the FE parser doesn't change.
 */
public record TokenResponseDto(
        String accessToken,
        String refreshToken,
        String idToken,
        long expiresIn,
        String tokenType
) {}
