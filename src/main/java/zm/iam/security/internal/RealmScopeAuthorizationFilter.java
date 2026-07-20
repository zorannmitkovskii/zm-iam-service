package zm.iam.security.internal;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;
import zm.iam.provisioning.ownership.ResourceOwnership;
import zm.iam.provisioning.ownership.ResourceOwnershipRepository;

import java.io.IOException;
import java.util.List;
import java.util.Optional;
import java.util.Set;

/**
 * The realm-scope authorization layer for {@code /internal/**}. Runs
 * AFTER Spring Security's JWT validation + role check have both
 * succeeded — at that point we know the caller is a valid zm-services
 * service account with the {@code iam-client} role. What we still need
 * to enforce is IAM-06's ownership contract: {@code ivy-events-be-svc}
 * must not be allowed to touch users in the {@code presmetko} realm
 * just because its token is valid.
 *
 * <p>Algorithm:
 * <ol>
 *   <li>Read {@code azp} from the JWT → derive serviceId via
 *       {@link ServiceIdFromAzp}. Bad azp → 403 (never 401 — the token
 *       IS valid, it just breaks our naming convention).</li>
 *   <li>Read {@code realm} query parameter. Missing → 400.</li>
 *   <li>Check {@link OwnedRealmsCache} — if the requested realm is not
 *       in the caller's owned set, 403 with a human-readable message
 *       telling them who DOES own it (helps operator debugging).</li>
 * </ol>
 *
 * <p>Response bodies match the {@link zm.iam.common.ApiResponse} shape
 * used everywhere else (success/message/data). Written directly rather
 * than via GlobalExceptionHandler because that handler sits behind the
 * security filter chain and never sees these short-circuit decisions.
 */
@Slf4j
@Component
public class RealmScopeAuthorizationFilter extends OncePerRequestFilter {

    private static final String REALM_PARAM = "realm";

    private final OwnedRealmsCache cache;
    private final ResourceOwnershipRepository ownershipRepository;
    private final InternalAuditLogger audit;

    public RealmScopeAuthorizationFilter(OwnedRealmsCache cache,
                                         ResourceOwnershipRepository ownershipRepository,
                                         InternalAuditLogger audit) {
        this.cache = cache;
        this.ownershipRepository = ownershipRepository;
        this.audit = audit;
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        // Only guard /internal/**. Everything else (provisioning,
        // actuator, public) is either covered by its own filter chain
        // or explicitly permitAll upstream.
        return !request.getRequestURI().startsWith("/internal/");
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {

        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        // The resource-server config in SecurityConfig gates on
        // hasRole("iam-client") BEFORE this filter runs, so a null
        // authentication should be unreachable. Defensive check
        // anyway — 401 rather than NPE if someone rewires the chain.
        if (!(auth instanceof JwtAuthenticationToken jwtAuth)) {
            deny(response, 401, "Missing or invalid bearer token");
            return;
        }

        Jwt jwt = jwtAuth.getToken();
        String azp = jwt.getClaimAsString("azp");
        String method = request.getMethod();
        String path = request.getRequestURI();

        if (!StringUtils.hasText(azp)) {
            audit.audit(InternalAuditLogger.Decision.DENIED_MISSING_AZP,
                    null, null, request.getParameter(REALM_PARAM), method, path, null);
            deny(response, 403, "Token missing required 'azp' claim");
            return;
        }

        Optional<String> serviceIdOpt = ServiceIdFromAzp.map(azp);
        if (serviceIdOpt.isEmpty()) {
            audit.audit(InternalAuditLogger.Decision.DENIED_BAD_AZP,
                    azp, null, request.getParameter(REALM_PARAM), method, path, null);
            deny(response, 403,
                    "Client '" + azp + "' does not follow the required '-svc' naming convention; "
                            + "IAM cannot map it to a service identity.");
            return;
        }
        String serviceId = serviceIdOpt.get();

        String requestedRealm = request.getParameter(REALM_PARAM);
        if (!StringUtils.hasText(requestedRealm)) {
            audit.audit(InternalAuditLogger.Decision.DENIED_MISSING_REALM_PARAM,
                    azp, serviceId, null, method, path, null);
            deny(response, 400,
                    "Missing required query parameter 'realm'");
            return;
        }

        Set<String> owned = cache.realmsFor(serviceId);
        if (!owned.contains(requestedRealm)) {
            String owner = lookupOwner(requestedRealm);
            audit.audit(InternalAuditLogger.Decision.DENIED_REALM_NOT_OWNED,
                    azp, serviceId, requestedRealm, method, path, owner);
            String ownerMsg = owner == null
                    ? "no service currently owns realm '" + requestedRealm + "'"
                    : "realm '" + requestedRealm + "' is owned by '" + owner + "'";
            deny(response, 403,
                    "Service '" + serviceId + "' is not authorised for realm '" + requestedRealm
                            + "' — " + ownerMsg + ".");
            return;
        }

        audit.audit(InternalAuditLogger.Decision.ALLOWED,
                azp, serviceId, requestedRealm, method, path, serviceId);
        chain.doFilter(request, response);
    }

    private String lookupOwner(String realm) {
        List<ResourceOwnership> rows =
                ownershipRepository.findAllByRealmOrderByResourceTypeAscResourceNameAsc(realm);
        // Prefer the REALM-level owner if present; otherwise fall back
        // to any owner row (client/idp). Null means truly unowned.
        return rows.stream()
                .filter(r -> r.getResourceName().equals(realm))
                .map(ResourceOwnership::getOwnerService)
                .findFirst()
                .orElseGet(() -> rows.stream()
                        .map(ResourceOwnership::getOwnerService)
                        .findFirst()
                        .orElse(null));
    }

    private void deny(HttpServletResponse response, int status, String message) throws IOException {
        response.setStatus(status);
        response.setContentType("application/json;charset=UTF-8");
        String body = "{\"success\":false,\"message\":\"" + escape(message) + "\",\"data\":null}";
        response.getWriter().write(body);
    }

    private static String escape(String s) {
        return s == null ? "" : s.replace("\\", "\\\\").replace("\"", "\\\"");
    }
}
