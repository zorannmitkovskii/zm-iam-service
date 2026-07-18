package org.ivyinc.iam.keycloak;

import jakarta.ws.rs.NotFoundException;
import lombok.extern.slf4j.Slf4j;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.resource.RealmResource;
import org.keycloak.representations.idm.RealmRepresentation;
import org.keycloak.representations.idm.RoleRepresentation;
import org.springframework.stereotype.Component;

/**
 * Thin typed facade over the Keycloak Admin REST API — the ONLY place in
 * IAM that calls Keycloak Admin API methods directly. Reconcilers, user
 * management, and {@link org.ivyinc.iam.keycloak.bootstrap.ServiceRealmProvisioner}
 * depend on this class instead of stringly touching {@link Keycloak}, so
 * we can add rate-limiting, tracing, or swap-out-the-transport without
 * ripple.
 *
 * <p>Scope in IAM-02 is deliberately narrow: realm existence check +
 * create, realm role existence check + create. Later tickets extend with
 * client, user, and attribute operations.
 */
@Slf4j
@Component
public class KeycloakAdminApi {

    private final KeycloakAdminSession session;

    public KeycloakAdminApi(KeycloakAdminSession session) {
        this.session = session;
    }

    // ── Realm operations ────────────────────────────────────────────

    /** {@code true} iff a realm with this exact name is present. */
    public boolean realmExists(String realmName) {
        try (Keycloak admin = session.client()) {
            // Cheaper than listing all realms: fetch this one by name; a
            // missing realm throws NotFoundException.
            admin.realm(realmName).toRepresentation();
            return true;
        } catch (NotFoundException e) {
            return false;
        }
    }

    /** Create a realm from the given representation. No-op safety: callers
     *  should check {@link #realmExists(String)} first — this method does
     *  NOT swallow "already exists" errors so double-creates are visible. */
    public void createRealm(RealmRepresentation representation) {
        try (Keycloak admin = session.client()) {
            admin.realms().create(representation);
            log.info("[KeycloakAdminApi] Created realm '{}'", representation.getRealm());
        }
    }

    // ── Realm role operations ───────────────────────────────────────

    public boolean realmRoleExists(String realmName, String roleName) {
        try (Keycloak admin = session.client()) {
            RealmResource realm = admin.realm(realmName);
            realm.roles().get(roleName).toRepresentation();
            return true;
        } catch (NotFoundException e) {
            return false;
        }
    }

    public void createRealmRole(String realmName, String roleName, String description) {
        RoleRepresentation role = new RoleRepresentation();
        role.setName(roleName);
        role.setDescription(description);
        role.setClientRole(false);
        try (Keycloak admin = session.client()) {
            admin.realm(realmName).roles().create(role);
            log.info("[KeycloakAdminApi] Created realm role '{}' in realm '{}'", roleName, realmName);
        }
    }
}
