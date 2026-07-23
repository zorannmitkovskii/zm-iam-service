package zm.iam.publicauth;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import zm.iam.common.ApiResponse;
import zm.iam.common.exception.BusinessException;
import zm.iam.common.exception.ErrorCode;
import zm.iam.publicauth.dto.LoginRequest;
import zm.iam.publicauth.dto.PasswordResetConfirmDto;
import zm.iam.publicauth.dto.PasswordResetRequestDto;
import zm.iam.publicauth.dto.RegisterRequest;
import zm.iam.publicauth.dto.TokenResponseDto;
import zm.iam.publicauth.dto.VerifyEmailRequest;

import java.util.Optional;

/**
 * IAM-10 public auth surface. Paths match ivy-events-be today so
 * nginx can route without FE / backend contract changes (see IVY-BE-04).
 *
 * <p>Every endpoint resolves the target realm via {@link RealmResolver}
 * (Origin header → realm map, {@code appId} body fallback). Unknown
 * origin without an appId → 400 — no silent default to prevent hitting
 * the wrong realm.
 *
 * <p>Rate limiting on register + password-reset — both open the door
 * to enumeration + abuse; login is throttled by Keycloak's own brute-
 * force policy (out of scope here).
 */
@Slf4j
@RestController
@RequestMapping("/public")
public class PublicAuthController {

    private final PublicAuthService service;
    private final RealmResolver realmResolver;
    private final PublicAuthRateLimiter rateLimiter;

    public PublicAuthController(PublicAuthService service,
                                 RealmResolver realmResolver,
                                 PublicAuthRateLimiter rateLimiter) {
        this.service = service;
        this.realmResolver = realmResolver;
        this.rateLimiter = rateLimiter;
    }

    // ── /users/register ──────────────────────────────────────────

    @PostMapping("/users/register")
    public ResponseEntity<ApiResponse<Void>> register(
            @Valid @RequestBody RegisterRequest req,
            @RequestHeader(value = "Origin", required = false) String origin,
            HttpServletRequest http) {
        String realm = requireRealm(origin, req.appId());
        String ip = clientIp(http);
        if (rateLimiter.isBlocked("register", ip, req.email(), PublicAuthRateLimiter.REGISTER_LIMIT)) {
            throw new BusinessException(ErrorCode.RATE_LIMITED,
                    "Too many registration attempts — try again later");
        }
        rateLimiter.recordAttempt("register", ip, req.email());
        service.register(realm, req);
        return ResponseEntity.ok(ApiResponse.ok(null));
    }

    // ── /auth/verify-email ───────────────────────────────────────

    @PostMapping("/auth/verify-email")
    public ResponseEntity<TokenResponseDto> verifyEmail(
            @Valid @RequestBody VerifyEmailRequest req,
            @RequestHeader(value = "Origin", required = false) String origin) {
        String realm = requireRealm(origin, req.appId());
        TokenResponseDto tokens = service.verifyEmail(realm, req);
        // Tokens returned at top level (NOT wrapped in ApiResponse) to match the
        // FE contract (auth.service.js reads data.accessToken directly).
        return ResponseEntity.ok(tokens);
    }

    // ── /users/login ─────────────────────────────────────────────

    @PostMapping("/users/login")
    public ResponseEntity<TokenResponseDto> login(
            @Valid @RequestBody LoginRequest req,
            @RequestHeader(value = "Origin", required = false) String origin) {
        String realm = requireRealm(origin, req.appId());
        TokenResponseDto tokens = service.login(realm, req);
        // Tokens returned at top level (NOT wrapped in ApiResponse) to match the
        // FE contract (auth.service.js reads data.accessToken directly).
        return ResponseEntity.ok(tokens);
    }

    // ── /password-reset ──────────────────────────────────────────

    @PostMapping("/password-reset/request")
    public ResponseEntity<ApiResponse<Void>> passwordResetRequest(
            @Valid @RequestBody PasswordResetRequestDto req,
            @RequestHeader(value = "Origin", required = false) String origin,
            HttpServletRequest http) {
        String realm = requireRealm(origin, req.appId());
        String ip = clientIp(http);
        if (rateLimiter.isBlocked("pwreset", ip, req.email(), PublicAuthRateLimiter.PASSWORD_RESET_LIMIT)) {
            throw new BusinessException(ErrorCode.RATE_LIMITED,
                    "Too many password reset requests — try again later");
        }
        rateLimiter.recordAttempt("pwreset", ip, req.email());
        service.requestPasswordReset(realm, req);
        return ResponseEntity.ok(ApiResponse.ok(null));
    }

    @PostMapping("/password-reset/confirm")
    public ResponseEntity<ApiResponse<Void>> passwordResetConfirm(
            @Valid @RequestBody PasswordResetConfirmDto req,
            @RequestHeader(value = "Origin", required = false) String origin) {
        String realm = requireRealm(origin, req.appId());
        service.confirmPasswordReset(realm, req);
        return ResponseEntity.ok(ApiResponse.ok(null));
    }

    // ── helpers ───────────────────────────────────────────────────

    private String requireRealm(String originHeader, String appId) {
        Optional<String> realm = realmResolver.resolve(originHeader, appId);
        if (realm.isEmpty()) {
            throw new BusinessException(ErrorCode.VALIDATION_ERROR,
                    "Could not resolve realm — send a known Origin header or a valid appId");
        }
        return realm.get();
    }

    private static String clientIp(HttpServletRequest req) {
        String fwd = req.getHeader("X-Forwarded-For");
        if (fwd != null && !fwd.isBlank()) return fwd.split(",")[0].trim();
        return req.getRemoteAddr();
    }
}
