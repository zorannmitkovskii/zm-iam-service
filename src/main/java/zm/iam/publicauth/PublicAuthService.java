package zm.iam.publicauth;

import lombok.extern.slf4j.Slf4j;
import org.keycloak.representations.idm.UserRepresentation;
import org.springframework.stereotype.Service;
import zm.iam.audit.AuditEvent;
import zm.iam.audit.AuditService;
import zm.iam.audit.TargetType;
import zm.iam.common.exception.BusinessException;
import zm.iam.common.exception.DuplicateResourceException;
import zm.iam.common.exception.ErrorCode;
import zm.iam.common.exception.ResourceNotFoundException;
import zm.iam.keycloak.KeycloakAdminApi;
import zm.iam.publicauth.notify.AuthNotificationGateway;
import zm.iam.publicauth.dto.ChangePasswordRequest;
import zm.iam.publicauth.dto.LoginRequest;
import zm.iam.publicauth.dto.PasswordResetConfirmDto;
import zm.iam.publicauth.dto.PasswordResetRequestDto;
import zm.iam.publicauth.dto.RegisterRequest;
import zm.iam.publicauth.dto.TokenResponseDto;
import zm.iam.publicauth.dto.VerifyEmailRequest;

import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * Coordinator for the public auth flows: register, verify email, login,
 * password reset (request + confirm) and change password. Delegates to
 * specialised collaborators; keeps its own logic thin.
 *
 * <p>Order-of-operations for register:
 * <ol>
 *   <li>Reject if user with same email exists in the resolved realm.</li>
 *   <li>Create the user DISABLED — a half-verified user shouldn't be
 *       able to log in.</li>
 *   <li>Set the password (non-temporary).</li>
 *   <li>Issue a verification code, email it, audit.</li>
 * </ol>
 * If the email send fails, the user is still there with a code — a
 * follow-up ticket adds an email retry queue (see IAM-10 §AC 9).
 */
@Slf4j
@Service
public class PublicAuthService {

    /** Keycloak user attribute marking an account still on its
     *  provisioned temporary password. */
    private static final String MUST_CHANGE_PASSWORD_ATTR = "mustChangePassword";

    private final KeycloakAdminApi keycloak;
    private final VerificationCodeService codes;
    private final AuthNotificationGateway notifications;
    private final KeycloakTokenClient tokens;
    private final AuditService audit;

    public PublicAuthService(KeycloakAdminApi keycloak,
                              VerificationCodeService codes,
                              AuthNotificationGateway notifications,
                              KeycloakTokenClient tokens,
                              AuditService audit) {
        this.keycloak = keycloak;
        this.codes = codes;
        this.notifications = notifications;
        this.tokens = tokens;
        this.audit = audit;
    }

    // ── Register ─────────────────────────────────────────────────

    public void register(String realm, RegisterRequest req) {
        if (keycloak.findUserByEmail(realm, req.email()).isPresent()) {
            audit.record(auditEvt(req.email(), realm, "REGISTER", false,
                    Map.of("reason", "duplicate_email")));
            throw new DuplicateResourceException(
                    "A user with email '" + req.email() + "' already exists in realm '" + realm + "'");
        }
        String userId = keycloak.createUser(realm, req.email(),
                req.firstName(), req.lastName(), /* enabled */ false);
        keycloak.resetUserPassword(realm, userId, req.password(), /* temporary */ false);

        String code = codes.issue(realm, req.email(), VerificationPurpose.EMAIL_VERIFY);
        notifications.emailVerification(realm, req.email(), code);

        audit.record(auditEvt(req.email(), realm, "REGISTER", true,
                Map.of("userId", userId)));
    }

    // ── Verify email ─────────────────────────────────────────────

    public TokenResponseDto verifyEmail(String realm, VerifyEmailRequest req) {
        VerificationCodeService.VerifyOutcome outcome =
                codes.verify(req.email(), VerificationPurpose.EMAIL_VERIFY, req.code());
        if (outcome != VerificationCodeService.VerifyOutcome.OK) {
            audit.record(auditEvt(req.email(), realm, "VERIFY_EMAIL", false,
                    Map.of("outcome", outcome.name())));
            throw verifyOutcomeToException(outcome);
        }
        // Flip enabled + assign USER role, then hand back tokens so FE
        // proceeds straight to dashboard.
        UserRepresentation user = keycloak.findUserByEmail(realm, req.email())
                .orElseThrow(() -> new ResourceNotFoundException(
                        "User with email '" + req.email() + "' not found in realm '" + realm + "'"));
        keycloak.setUserEnabled(realm, user.getId(), true);
        keycloak.addUserRealmRoles(realm, user.getId(), List.of("USER"));

        audit.record(auditEvt(req.email(), realm, "VERIFY_EMAIL", true,
                Map.of("userId", user.getId())));

        // NOTE: Log user in with a temporary password grant IS the natural
        // move here, but we'd need the plaintext password — verify-email
        // only knows the code. Options: (a) skip auto-login, FE sees 200
        // + calls /login itself; (b) issue Keycloak's client_credentials +
        // token exchange (complex). Simplest: auto-login only when the
        // request body carried the password again (Ivy today does re-post).
        // For MVP, return an empty token response so FE calls /login next.
        return new TokenResponseDto(null, null, null, 0, "verified");
    }

    // ── Login ─────────────────────────────────────────────────────

    public TokenResponseDto login(String realm, LoginRequest req) {
        try {
            KeycloakTokenClient.TokenResponse resp =
                    tokens.passwordGrant(realm, req.username(), req.password());
            audit.record(auditEvt(req.username(), realm, "LOGIN", true, Map.of()));
            return new TokenResponseDto(
                    resp.accessToken(), resp.refreshToken(), resp.idToken(),
                    resp.expiresIn(), resp.tokenType());
        } catch (KeycloakTokenClient.PasswordGrantException e) {
            audit.record(auditEvt(req.username(), realm, "LOGIN", false,
                    Map.of("keycloakStatus", e.getStatus())));
            throw new BusinessException(ErrorCode.AUTHN_FAILED, "Invalid credentials");
        }
    }

    // ── Password reset — request ─────────────────────────────────

    public void requestPasswordReset(String realm, PasswordResetRequestDto req) {
        // Deliberately do NOT reveal whether the email exists — always
        // return 200 to prevent user enumeration.
        Optional<UserRepresentation> maybe = keycloak.findUserByEmail(realm, req.email());
        if (maybe.isPresent()) {
            String code = codes.issue(realm, req.email(), VerificationPurpose.PASSWORD_RESET);
            notifications.passwordReset(realm, req.email(), code);
        } else {
            log.info("[PublicAuth] Password reset requested for unknown email={} realm={} — silent 200",
                    req.email(), realm);
        }
        audit.record(auditEvt(req.email(), realm, "PASSWORD_RESET_REQUEST",
                maybe.isPresent(), Map.of()));
    }

    // ── Password reset — confirm ─────────────────────────────────

    public void confirmPasswordReset(String realm, PasswordResetConfirmDto req) {
        VerificationCodeService.VerifyOutcome outcome =
                codes.verify(req.email(), VerificationPurpose.PASSWORD_RESET, req.code());
        if (outcome != VerificationCodeService.VerifyOutcome.OK) {
            audit.record(auditEvt(req.email(), realm, "PASSWORD_RESET_CONFIRM", false,
                    Map.of("outcome", outcome.name())));
            throw verifyOutcomeToException(outcome);
        }
        UserRepresentation user = keycloak.findUserByEmail(realm, req.email())
                .orElseThrow(() -> new ResourceNotFoundException(
                        "User with email '" + req.email() + "' not found in realm '" + realm + "'"));
        keycloak.resetUserPassword(realm, user.getId(), req.newPassword(), /* temporary */ false);
        audit.record(auditEvt(req.email(), realm, "PASSWORD_RESET_CONFIRM", true,
                Map.of("userId", user.getId())));
    }

    // ── Change password ──────────────────────────────────────────

    /**
     * Change a password for a caller who proves the current one. The proof
     * is a password grant against the realm — the same check Keycloak would
     * apply at login, so a wrong current password fails here exactly as it
     * would there, brute-force policy included.
     *
     * <p>Clears {@code mustChangePassword} on success: an account
     * provisioned with a temporary password carries that flag, and leaving
     * it set would send the user back through this flow on every login.
     */
    public void changePassword(String realm, ChangePasswordRequest req) {
        try {
            tokens.passwordGrant(realm, req.email(), req.currentPassword());
        } catch (KeycloakTokenClient.PasswordGrantException e) {
            audit.record(auditEvt(req.email(), realm, "CHANGE_PASSWORD", false,
                    Map.of("reason", "bad_current_password", "keycloakStatus", e.getStatus())));
            throw new BusinessException(ErrorCode.AUTHN_FAILED, "Current password is incorrect");
        }
        UserRepresentation user = keycloak.findUserByEmail(realm, req.email())
                .orElseThrow(() -> new ResourceNotFoundException(
                        "User with email '" + req.email() + "' not found in realm '" + realm + "'"));
        keycloak.resetUserPassword(realm, user.getId(), req.newPassword(), /* temporary */ false);
        keycloak.removeUserAttribute(realm, user.getId(), MUST_CHANGE_PASSWORD_ATTR);
        audit.record(auditEvt(req.email(), realm, "CHANGE_PASSWORD", true,
                Map.of("userId", user.getId())));
    }

    // ── helpers ───────────────────────────────────────────────────

    private static BusinessException verifyOutcomeToException(VerificationCodeService.VerifyOutcome o) {
        return switch (o) {
            case NOT_FOUND, EXPIRED -> new BusinessException(ErrorCode.VALIDATION_ERROR,
                    "Verification code is invalid or expired");
            case MISMATCH -> new BusinessException(ErrorCode.VALIDATION_ERROR,
                    "Verification code does not match");
            case LOCKED_OUT -> new BusinessException(ErrorCode.VALIDATION_ERROR,
                    "Too many wrong attempts — request a new code");
            default -> new BusinessException(ErrorCode.INTERNAL_SERVER_ERROR,
                    "Unexpected verification outcome");
        };
    }

    private AuditEvent auditEvt(String email, String realm, String op, boolean success,
                                 Map<String, Object> extraDetail) {
        Map<String, Object> detail = new java.util.HashMap<>(extraDetail);
        return AuditEvent.builder()
                .caller("PUBLIC:" + zm.iam.audit.PiiMasker.maskEmail(email))
                .realm(realm)
                .targetType(TargetType.USER)
                .targetId(zm.iam.audit.PiiMasker.maskEmail(email))
                .operation(op)
                .detail(detail)
                .success(success)
                .build();
    }
}
