package zm.iam.publicauth;

/**
 * Boundary for outbound transactional email. IAM-10 ships two
 * implementations: {@link LoggingEmailSender} (default — writes an INFO
 * line so local dev + tests can inspect the code without a real SMTP)
 * and — when the ZeptoMail integration lands as its own IAM ticket —
 * {@code ZeptoMailEmailSender} that hits the real HTTP API.
 *
 * <p>Templates are realm-aware ({@link EmailTemplate#brand} carries the
 * app name/link overrides). Ivy sees the same subject lines it sees
 * today so users don't notice the migration.
 */
public interface EmailSender {

    void send(String realm, String toEmail, EmailTemplate template);

    /** Placeholder for the (subject, body, brand) triple. Real
     *  implementation gets richer (HTML + text alternatives, links). */
    record EmailTemplate(String subject, String body, String brand) {

        public static EmailTemplate verificationCode(String code, String brand) {
            return new EmailTemplate(
                    "Your " + brand + " verification code",
                    "Your verification code is: " + code + "\n\nIt expires in 10 minutes.",
                    brand);
        }

        public static EmailTemplate passwordResetCode(String code, String brand) {
            return new EmailTemplate(
                    "Reset your " + brand + " password",
                    "To reset your password, enter this code: " + code
                            + "\n\nIt expires in 10 minutes. If you didn't request a reset, ignore this email.",
                    brand);
        }
    }
}
