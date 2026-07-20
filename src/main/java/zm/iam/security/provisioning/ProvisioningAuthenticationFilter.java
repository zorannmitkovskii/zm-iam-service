package zm.iam.security.provisioning;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpMethod;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.argon2.Argon2PasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.util.ContentCachingRequestWrapper;

import java.io.IOException;
import java.util.List;
import java.util.Optional;

/**
 * The IAM-05 gate for {@code /provisioning/**}.
 *
 * <p>Flow, in order:
 * <ol>
 *   <li>If the client IP is over its failure budget → 429.</li>
 *   <li>No {@code X-Provisioning-Token} header → 401.</li>
 *   <li>Cannot determine target {@code serviceId} from request → 400.</li>
 *   <li>No hashes registered for that serviceId → 401 (masquerades as
 *       "token invalid" so we don't leak service enumeration).</li>
 *   <li>Argon2 verify against every accepted hash (rotation supported)
 *       → any match sets the authentication and chains; none match →
 *       401.</li>
 *   <li>Match is against a service DIFFERENT from the one in the
 *       request → 403.</li>
 * </ol>
 *
 * <p>Body is peeked via {@link ContentCachingRequestWrapper}; the
 * controller downstream sees the same bytes.
 */
@Slf4j
@Component
public class ProvisioningAuthenticationFilter extends OncePerRequestFilter {

    public static final String HEADER = "X-Provisioning-Token";

    private final TokenRegistry tokenRegistry;
    private final ServiceIdExtractor serviceIdExtractor;
    private final ProvisioningRateLimiter rateLimiter;
    private final AuthAuditLogger audit;
    private final PasswordEncoder argon2;

    public ProvisioningAuthenticationFilter(TokenRegistry tokenRegistry,
                                            ServiceIdExtractor serviceIdExtractor,
                                            ProvisioningRateLimiter rateLimiter,
                                            AuthAuditLogger audit) {
        this.tokenRegistry = tokenRegistry;
        this.serviceIdExtractor = serviceIdExtractor;
        this.rateLimiter = rateLimiter;
        this.audit = audit;
        // Spring's Argon2PasswordEncoder — constant-time verify via matches().
        // Defaults line up with the values our helper script uses to hash
        // plaintext tokens (see scripts/generate-provisioning-token.sh).
        this.argon2 = Argon2PasswordEncoder.defaultsForSpringSecurity_v5_8();
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        String uri = request.getRequestURI();
        if (!uri.startsWith("/provisioning/")) return true;
        // /validate is public (dry-run, no Keycloak side effect) — see
        // SecurityConfig.permitAll for the matching authz rule.
        return "/provisioning/manifests/validate".equals(uri);
    }

    @Value("${iam.provisioning.security-enabled:true}")
    private boolean enabled;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {

        if (!enabled) {
            // Escape hatch for tests / early staging that don't want the
            // filter engaged. Prod MUST leave this at default (true).
            chain.doFilter(request, response);
            return;
        }

        String clientIp = clientIp(request);
        String path = request.getRequestURI();

        if (rateLimiter.isBlocked(clientIp)) {
            audit.audit(AuthAuditLogger.Decision.RATE_LIMITED, null, null, clientIp, path, 0);
            deny(response, 429, "Too many failed attempts");
            return;
        }

        String token = request.getHeader(HEADER);
        int tokenLen = token == null ? 0 : token.length();
        if (!StringUtils.hasText(token)) {
            rateLimiter.recordFailure(clientIp);
            audit.audit(AuthAuditLogger.Decision.DENIED_MISSING_HEADER, null, null, clientIp, path, 0);
            deny(response, HttpServletResponse.SC_UNAUTHORIZED,
                    "Missing " + HEADER + " header");
            return;
        }

        // POST needs the body; wrap once so the controller sees the same
        // bytes. GET path variable is enough on its own.
        ContentCachingRequestWrapper wrapped = new ContentCachingRequestWrapper(request);
        if (HttpMethod.POST.matches(request.getMethod())) {
            // Force read so the cache is populated before we peek.
            wrapped.getInputStream().readAllBytes();
        }

        Optional<String> requestedServiceId =
                serviceIdExtractor.extract(wrapped, wrapped.getContentAsByteArray());
        if (requestedServiceId.isEmpty()) {
            rateLimiter.recordFailure(clientIp);
            audit.audit(AuthAuditLogger.Decision.DENIED_SERVICEID_MISMATCH,
                    null, null, clientIp, path, tokenLen);
            deny(response, HttpServletResponse.SC_BAD_REQUEST,
                    "Could not determine target serviceId from request");
            return;
        }

        String targetService = requestedServiceId.get();
        String matchedService = verifyAgainstAnyKnownService(token);

        if (matchedService == null) {
            rateLimiter.recordFailure(clientIp);
            audit.audit(AuthAuditLogger.Decision.DENIED_TOKEN_INVALID,
                    null, targetService, clientIp, path, tokenLen);
            deny(response, HttpServletResponse.SC_UNAUTHORIZED, "Invalid provisioning token");
            return;
        }

        if (!matchedService.equals(targetService)) {
            // Do NOT count as failure — the token IS valid, just for a
            // different service. Counting would let a legit service be
            // rate-limited by an attacker who knows its token but targets
            // another service.
            audit.audit(AuthAuditLogger.Decision.DENIED_SERVICEID_MISMATCH,
                    matchedService, targetService, clientIp, path, tokenLen);
            deny(response, HttpServletResponse.SC_FORBIDDEN,
                    "Token authenticates as service '" + matchedService
                            + "' but request targets '" + targetService + "'");
            return;
        }

        var auth = new ProvisioningTokenAuthentication(matchedService);
        SecurityContextHolder.getContext().setAuthentication(auth);
        audit.audit(AuthAuditLogger.Decision.ALLOWED,
                matchedService, targetService, clientIp, path, tokenLen);
        try {
            chain.doFilter(wrapped, response);
        } finally {
            SecurityContextHolder.clearContext();
        }
    }

    /** Iterate every registered service + every hash on it. Returns the
     *  matching serviceId or {@code null}. Iteration order is irrelevant
     *  — a plaintext token that matches ANY hash authenticates as
     *  whichever service owns that hash. */
    private String verifyAgainstAnyKnownService(String plaintextToken) {
        for (var e : tokenRegistry.snapshot().entrySet()) {
            for (String hash : e.getValue()) {
                if (argon2.matches(plaintextToken, hash)) {
                    return e.getKey();
                }
            }
        }
        return null;
    }

    private static String clientIp(HttpServletRequest req) {
        String fwd = req.getHeader("X-Forwarded-For");
        if (StringUtils.hasText(fwd)) return fwd.split(",")[0].trim();
        return req.getRemoteAddr();
    }

    private void deny(HttpServletResponse response, int status, String message) throws IOException {
        response.setStatus(status);
        response.setContentType("application/json;charset=UTF-8");
        // Keep body shape consistent with GlobalExceptionHandler's ApiResponse.
        String body = "{\"success\":false,\"message\":\"" + escape(message)
                + "\",\"data\":null}";
        response.getWriter().write(body);
    }

    private static String escape(String s) {
        return s == null ? "" : s.replace("\\", "\\\\").replace("\"", "\\\"");
    }

    // Kept for a follow-up if we ever want to expose which hash matched
    // (never expose to the client — audit table only).
    @SuppressWarnings("unused")
    private List<String> hashesFor(String serviceId) {
        return tokenRegistry.hashesFor(serviceId);
    }
}
