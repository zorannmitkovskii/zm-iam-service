package zm.iam.user;

import jakarta.ws.rs.NotFoundException;
import lombok.extern.slf4j.Slf4j;
import org.keycloak.representations.idm.RoleRepresentation;
import org.keycloak.representations.idm.UserRepresentation;
import org.springframework.stereotype.Service;
import zm.iam.common.exception.DuplicateResourceException;
import zm.iam.common.exception.ResourceNotFoundException;
import zm.iam.keycloak.KeycloakAdminApi;
import zm.iam.user.audit.AuditService;
import zm.iam.user.dto.AttributePatchDto;
import zm.iam.user.dto.RolesPutDto;
import zm.iam.user.dto.UserCreateDto;
import zm.iam.user.dto.UserResponseDto;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * The single write path for Keycloak user state. Every mutation:
 * <ol>
 *   <li>Loads current state (defence against stale caller data).</li>
 *   <li>Takes the per-user JVM stripe so concurrent PATCH/PUT
 *       serialise into ordered read-modify-write blocks.</li>
 *   <li>Writes back once, then emits an audit line.</li>
 * </ol>
 *
 * <p>Realm existence is verified up-front so a bad realm gets 404
 * without wasting a user lookup.
 */
@Slf4j
@Service
public class UserService {

    private final KeycloakAdminApi keycloak;
    private final UserStripedLock stripe;
    private final AuditService audit;

    public UserService(KeycloakAdminApi keycloak, UserStripedLock stripe, AuditService audit) {
        this.keycloak = keycloak;
        this.stripe = stripe;
        this.audit = audit;
    }

    // ── Create ──────────────────────────────────────────────────

    public UserResponseDto create(String realm, UserCreateDto dto) {
        requireRealm(realm);
        if (!keycloak.findUsersByEmail(realm, dto.email()).isEmpty()) {
            throw new DuplicateResourceException(
                    "A user with email '" + dto.email() + "' already exists in realm '" + realm + "'");
        }

        UserRepresentation body = new UserRepresentation();
        body.setEmail(dto.email());
        body.setUsername(dto.email());  // Ivy convention — email doubles as username
        body.setFirstName(dto.firstName());
        body.setLastName(dto.lastName());
        body.setEnabled(dto.enabled() == null ? Boolean.TRUE : dto.enabled());
        body.setEmailVerified(false);
        if (dto.attributes() != null && !dto.attributes().isEmpty()) {
            body.setAttributes(new HashMap<>(dto.attributes()));
        }

        String userId;
        try {
            userId = keycloak.createUser(realm, body);
        } catch (KeycloakAdminApi.KeycloakApiException e) {
            if (e.status() == 409) {
                throw new DuplicateResourceException(
                        "A user with email '" + dto.email() + "' already exists in realm '" + realm + "'");
            }
            throw e;
        }

        // Temporary password + realm roles are separate calls Keycloak
        // requires — do them under the stripe so a paralleljob PATCHing
        // roles right after the create doesn't race the initial add.
        synchronized (stripe.lockFor(realm, userId)) {
            if (dto.temporaryPassword() != null && !dto.temporaryPassword().isBlank()) {
                keycloak.resetPassword(realm, userId, dto.temporaryPassword(), true);
                audit.record("PASSWORD_RESET", realm, userId, "temporary=true (initial)");
            }
            if (dto.realmRoles() != null && !dto.realmRoles().isEmpty()) {
                List<RoleRepresentation> roles = keycloak.findRealmRoleReps(realm, dto.realmRoles());
                keycloak.addUserRealmRoles(realm, userId, roles);
                audit.record("ROLES_UPDATED", realm, userId, "added=" + dto.realmRoles());
            }
        }

        audit.record("USER_CREATED", realm, userId, "email=" + dto.email());
        return get(realm, userId);
    }

    // ── Read ────────────────────────────────────────────────────

    public UserResponseDto get(String realm, String userId) {
        requireRealm(realm);
        UserRepresentation rep = keycloak.findUser(realm, userId)
                .orElseThrow(() -> userNotFound(realm, userId));
        List<String> roles = keycloak.getUserRealmRoles(realm, userId).stream()
                .map(RoleRepresentation::getName)
                .collect(Collectors.toList());
        return map(rep, roles);
    }

    public Optional<UserResponseDto> searchByEmail(String realm, String email) {
        requireRealm(realm);
        List<UserRepresentation> hits = keycloak.findUsersByEmail(realm, email);
        if (hits.isEmpty()) return Optional.empty();
        UserRepresentation hit = hits.get(0);
        List<String> roles = keycloak.getUserRealmRoles(realm, hit.getId()).stream()
                .map(RoleRepresentation::getName)
                .collect(Collectors.toList());
        return Optional.of(map(hit, roles));
    }

    // ── Delete ──────────────────────────────────────────────────

    public void delete(String realm, String userId) {
        requireRealm(realm);
        synchronized (stripe.lockFor(realm, userId)) {
            try {
                keycloak.deleteUser(realm, userId);
            } catch (NotFoundException e) {
                throw userNotFound(realm, userId);
            }
            audit.record("USER_DELETED", realm, userId, null);
        }
    }

    // ── Roles ───────────────────────────────────────────────────

    /** Declarative PUT — computes and applies the diff against current
     *  realm-level roles. Empty target list removes every realm role. */
    public UserResponseDto putRoles(String realm, String userId, RolesPutDto dto) {
        requireRealm(realm);
        synchronized (stripe.lockFor(realm, userId)) {
            requireUser(realm, userId);
            List<RoleRepresentation> current = keycloak.getUserRealmRoles(realm, userId);
            Set<String> currentNames = current.stream()
                    .map(RoleRepresentation::getName).collect(Collectors.toSet());
            Set<String> desired = new HashSet<>(dto.roles());

            List<String> toAddNames = dto.roles().stream()
                    .filter(n -> !currentNames.contains(n)).collect(Collectors.toList());
            List<RoleRepresentation> toRemove = current.stream()
                    .filter(r -> !desired.contains(r.getName())).collect(Collectors.toList());

            if (!toAddNames.isEmpty()) {
                keycloak.addUserRealmRoles(realm, userId, keycloak.findRealmRoleReps(realm, toAddNames));
            }
            if (!toRemove.isEmpty()) {
                keycloak.removeUserRealmRoles(realm, userId, toRemove);
            }

            audit.record("ROLES_UPDATED", realm, userId,
                    "added=" + toAddNames + " removed=" + toRemove.stream()
                            .map(RoleRepresentation::getName).toList());
        }
        return get(realm, userId);
    }

    // ── Attributes patch ───────────────────────────────────────

    public UserResponseDto patchAttributes(String realm, String userId, AttributePatchDto patch) {
        requireRealm(realm);
        synchronized (stripe.lockFor(realm, userId)) {
            UserRepresentation user = keycloak.findUser(realm, userId)
                    .orElseThrow(() -> userNotFound(realm, userId));
            Map<String, List<String>> merged = AttributePatcher.merge(user.getAttributes(), patch);
            user.setAttributes(new HashMap<>(merged));
            keycloak.updateUser(realm, userId, user);
            audit.record("ATTRIBUTES_PATCHED", realm, userId,
                    "keys=" + patchedKeys(patch));
        }
        return get(realm, userId);
    }

    // ── Enable / disable ───────────────────────────────────────

    public UserResponseDto setEnabled(String realm, String userId, boolean enabled) {
        requireRealm(realm);
        synchronized (stripe.lockFor(realm, userId)) {
            UserRepresentation user = keycloak.findUser(realm, userId)
                    .orElseThrow(() -> userNotFound(realm, userId));
            user.setEnabled(enabled);
            keycloak.updateUser(realm, userId, user);
            audit.record(enabled ? "USER_ENABLED" : "USER_DISABLED", realm, userId, null);
        }
        return get(realm, userId);
    }

    // ── helpers ────────────────────────────────────────────────

    private void requireRealm(String realm) {
        if (!keycloak.realmExists(realm)) {
            throw new ResourceNotFoundException("Realm '" + realm + "' not found");
        }
    }

    private void requireUser(String realm, String userId) {
        if (keycloak.findUser(realm, userId).isEmpty()) {
            throw userNotFound(realm, userId);
        }
    }

    private static ResourceNotFoundException userNotFound(String realm, String userId) {
        return new ResourceNotFoundException(
                "User id='" + userId + "' not found in realm '" + realm + "'");
    }

    private static UserResponseDto map(UserRepresentation rep, List<String> roles) {
        return new UserResponseDto(
                rep.getId(),
                rep.getEmail(),
                rep.getFirstName(),
                rep.getLastName(),
                Boolean.TRUE.equals(rep.isEnabled()),
                rep.getAttributes() == null ? Map.of() : new HashMap<>(rep.getAttributes()),
                roles);
    }

    private static List<String> patchedKeys(AttributePatchDto p) {
        List<String> keys = new ArrayList<>();
        if (p.set() != null) keys.addAll(p.set().keySet());
        if (p.append() != null) keys.addAll(p.append().keySet());
        if (p.remove() != null) keys.addAll(p.remove().keySet());
        return keys;
    }
}
