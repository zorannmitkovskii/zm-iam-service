package zm.iam.publicauth;

/**
 * Why a verification code was issued. Purpose is part of the lookup key
 * so a valid password-reset code can never be replayed as an
 * email-verification code (different DB rows, different consumption
 * state).
 */
public enum VerificationPurpose {
    EMAIL_VERIFY,
    PASSWORD_RESET
}
