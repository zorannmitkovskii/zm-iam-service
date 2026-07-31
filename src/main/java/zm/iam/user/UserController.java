package zm.iam.user;

import jakarta.validation.Valid;
import jakarta.ws.rs.NotFoundException;
import lombok.extern.slf4j.Slf4j;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.representations.idm.UserRepresentation;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import zm.iam.common.ApiResponse;
import zm.iam.common.exception.BusinessException;
import zm.iam.common.exception.ErrorCode;
import zm.iam.keycloak.KeycloakAdminApi;
import zm.iam.user.dto.AttributePatchRequest;
import zm.iam.keycloak.KeycloakAdminSession;

import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Placeholder for the internal user-management HTTP surface. IAM-09
 * lands the security perimeter; the concrete CRUD endpoints (create,
 * update, delete, role assignment) land in IAM-10/11. For now we ship
 * a single {@code /internal/users/search} endpoint so:
 *
 * <ul>
 *   <li>The IAM-09 integration test has a real controller to hit
 *       (any 2xx confirms the filter chain let the request through).</li>
 *   <li>Downstream services (ivy-events-be) can start wiring the
 *       search call and get a 501-style stub rather than 404 until
 *       IAM-10 fills in the body.</li>
 * </ul>
 *
 * <p>Every path here is under {@code /internal/**} and therefore
 * covered by the JWT + realm-scope filter chain in
 * {@link zm.iam.security.config.SecurityConfig}. The controller itself
 * does NOT re-check authorization — the filter did the work.
 */
@Slf4j
@RestController
@RequestMapping("/internal/users")
public class UserController {

    private final KeycloakAdminSession session;
    private final KeycloakAdminApi keycloak;

    public UserController(KeycloakAdminSession session, KeycloakAdminApi keycloak) {
        this.session = session;
        this.keycloak = keycloak;
    }

    /**
     * Search users in a realm by email (best-effort) or username. Both
     * query parameters are optional; if both are absent, returns the
     * first page of users so callers can smoke-test the endpoint. The
     * {@code realm} query parameter is REQUIRED and already validated
     * by the realm-scope filter — by the time we get here we know the
     * caller owns it.
     */
    @GetMapping("/search")
    public ResponseEntity<ApiResponse<Map<String, Object>>> search(
            @RequestParam String realm,
            @RequestParam(required = false) String email,
            @RequestParam(required = false) String username) {

        List<UserRepresentation> users;
        try (Keycloak admin = session.client()) {
            if (email != null && !email.isBlank()) {
                users = admin.realm(realm).users().searchByEmail(email, true);
            } else if (username != null && !username.isBlank()) {
                users = admin.realm(realm).users().searchByUsername(username, true);
            } else {
                // First-page listing — same shape as the search response,
                // useful for smoke tests + operator introspection.
                users = admin.realm(realm).users().list(0, 20);
            }
        } catch (NotFoundException nf) {
            // Requested realm doesn't exist in Keycloak — return empty
            // rather than 404. The security filter already confirmed
            // ownership, so this represents a state drift between our
            // ownership rows and Keycloak; log it and let the caller
            // deal with the empty result.
            log.warn("[UserController] Realm '{}' owned by caller but missing in Keycloak", realm);
            users = Collections.emptyList();
        }
        return ResponseEntity.ok(ApiResponse.ok(Map.of(
                "realm", realm,
                "count", users.size(),
                "users", users.stream().map(UserController::project).toList()
        )));
    }

    /**
     * Applies set / append / remove to one user's attributes.
     *
     * <p>This is what puts an event in a user's {@code eventIds}. Ivy calls it
     * whenever an event is created: it is the only writer, because access is
     * decided from that claim and nothing else, and because ivy-events-be is
     * not allowed near the Keycloak Admin API.
     *
     * <p>The three buckets are applied in the order named. A key present in
     * both {@code set} and {@code append} is a caller bug — the two disagree
     * about what the attribute should end up as — and is refused rather than
     * silently resolved by ordering.
     *
     * <p>An attribute must be declared in the realm's user profile or Keycloak
     * discards it without complaint: the write returns 204 and stores nothing.
     * That is not theoretical — it is exactly how {@code eventIds} came to be
     * empty for every user while the code writing it looked correct.
     */
    @PatchMapping("/{userId}/attributes")
    public ResponseEntity<ApiResponse<Map<String, Object>>> patchAttributes(
            @PathVariable String userId,
            @RequestParam String realm,
            @Valid @RequestBody AttributePatchRequest request) {

        if (request.set() != null && request.append() != null) {
            Set<String> both = new java.util.HashSet<>(request.set().keySet());
            both.retainAll(request.append().keySet());
            if (!both.isEmpty()) {
                throw new BusinessException(ErrorCode.VALIDATION_ERROR,
                        "set and append name the same attribute(s): " + both);
            }
        }

        UserRepresentation updated = keycloak.patchUserAttributes(
                realm, userId, request.set(), request.append(), request.remove());

        return ResponseEntity.ok(ApiResponse.ok(projectWithAttributes(updated)));
    }

    /** Same projection as {@link #project}, plus the attributes the caller
     *  just changed — a caller that patches wants to see the result. */
    private static Map<String, Object> projectWithAttributes(UserRepresentation u) {
        Map<String, Object> m = new java.util.LinkedHashMap<>(project(u));
        m.put("attributes", u.getAttributes() == null ? Map.of() : u.getAttributes());
        return m;
    }

    /** Project only the fields safe to expose over the internal API —
     *  drop credentials, secrets, and Keycloak-specific ids the caller
     *  can't use anyway. */
    private static Map<String, Object> project(UserRepresentation u) {
        Map<String, Object> m = new java.util.LinkedHashMap<>();
        m.put("id", u.getId());
        m.put("username", u.getUsername());
        m.put("email", u.getEmail());
        m.put("firstName", u.getFirstName());
        m.put("lastName", u.getLastName());
        m.put("enabled", u.isEnabled());
        return m;
    }
}
