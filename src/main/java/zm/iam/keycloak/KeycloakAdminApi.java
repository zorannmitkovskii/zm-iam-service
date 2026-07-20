package zm.iam.keycloak;

import jakarta.ws.rs.NotFoundException;
import jakarta.ws.rs.core.Response;
import lombok.extern.slf4j.Slf4j;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.resource.ClientResource;
import org.keycloak.admin.client.resource.RealmResource;
import org.keycloak.admin.client.resource.UserResource;
import org.keycloak.representations.idm.ClientRepresentation;
import org.keycloak.representations.idm.CredentialRepresentation;
import org.keycloak.representations.idm.IdentityProviderRepresentation;
import org.keycloak.representations.idm.ProtocolMapperRepresentation;
import org.keycloak.representations.idm.RealmRepresentation;
import org.keycloak.representations.idm.RoleRepresentation;
import org.keycloak.representations.idm.UserRepresentation;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

/**
 * Thin typed facade over the Keycloak Admin REST API — the ONLY place in
 * IAM that calls Keycloak Admin API methods directly. Reconcilers and
 * {@link zm.iam.keycloak.bootstrap.ServiceRealmProvisioner}
 * depend on this class rather than stringly-touching {@link Keycloak},
 * so we can add rate-limiting, tracing, or swap-out-the-transport
 * without ripple.
 *
 * <p>Scope in IAM-04: realm read/create/update, client CRUD, protocol
 * mapper CRUD, identity provider CRUD, realm role create-if-missing.
 * User-profile attribute handling is deferred (Keycloak's User Profile
 * API needs its own IAM ticket).
 */
@Slf4j
@Component
public class KeycloakAdminApi {

    private final KeycloakAdminSession session;

    public KeycloakAdminApi(KeycloakAdminSession session) {
        this.session = session;
    }

    // ── Realm ───────────────────────────────────────────────────────

    public Optional<RealmRepresentation> findRealm(String realmName) {
        try (Keycloak admin = session.client()) {
            return Optional.of(admin.realm(realmName).toRepresentation());
        } catch (NotFoundException e) {
            return Optional.empty();
        }
    }

    public boolean realmExists(String realmName) {
        return findRealm(realmName).isPresent();
    }

    /** Create a realm. Callers should check existence first — this method
     *  does NOT swallow "already exists" errors, so double-creates are
     *  visible. */
    public void createRealm(RealmRepresentation representation) {
        try (Keycloak admin = session.client()) {
            admin.realms().create(representation);
            log.info("[KeycloakAdminApi] Created realm '{}'", representation.getRealm());
        }
    }

    /** Partial update — Keycloak's PUT on realm merges non-null fields,
     *  so we can safely send only the settings we manage. */
    public void updateRealm(String realmName, RealmRepresentation partial) {
        try (Keycloak admin = session.client()) {
            admin.realm(realmName).update(partial);
            log.info("[KeycloakAdminApi] Updated realm '{}'", realmName);
        }
    }

    // ── Clients ─────────────────────────────────────────────────────

    public List<ClientRepresentation> listClients(String realmName) {
        try (Keycloak admin = session.client()) {
            return admin.realm(realmName).clients().findAll();
        }
    }

    /** Business-clientId lookup — internal UUID is what update calls need. */
    public Optional<ClientRepresentation> findClient(String realmName, String clientId) {
        try (Keycloak admin = session.client()) {
            List<ClientRepresentation> hits = admin.realm(realmName).clients().findByClientId(clientId);
            return hits.isEmpty() ? Optional.empty() : Optional.of(hits.get(0));
        }
    }

    public void createClient(String realmName, ClientRepresentation client) {
        try (Keycloak admin = session.client()) {
            admin.realm(realmName).clients().create(client);
            log.info("[KeycloakAdminApi] Created client '{}' in realm '{}'",
                    client.getClientId(), realmName);
        }
    }

    /** {@code representation.id} MUST be the Keycloak UUID — the update
     *  endpoint keys on internal id, not business clientId. */
    public void updateClient(String realmName, ClientRepresentation representation) {
        try (Keycloak admin = session.client()) {
            RealmResource realm = admin.realm(realmName);
            ClientResource clientResource = realm.clients().get(representation.getId());
            clientResource.update(representation);
            log.info("[KeycloakAdminApi] Updated client '{}' (uuid={}) in realm '{}'",
                    representation.getClientId(), representation.getId(), realmName);
        }
    }

    // ── Protocol mappers ────────────────────────────────────────────

    public List<ProtocolMapperRepresentation> listProtocolMappers(String realmName, String clientUuid) {
        try (Keycloak admin = session.client()) {
            return admin.realm(realmName).clients().get(clientUuid).getProtocolMappers().getMappers();
        }
    }

    public void createProtocolMapper(String realmName, String clientUuid, ProtocolMapperRepresentation mapper) {
        try (Keycloak admin = session.client()) {
            admin.realm(realmName).clients().get(clientUuid).getProtocolMappers().createMapper(mapper);
            log.info("[KeycloakAdminApi] Created protocol mapper '{}' on client uuid={}",
                    mapper.getName(), clientUuid);
        }
    }

    public void updateProtocolMapper(String realmName, String clientUuid, ProtocolMapperRepresentation mapper) {
        try (Keycloak admin = session.client()) {
            admin.realm(realmName).clients().get(clientUuid).getProtocolMappers()
                    .update(mapper.getId(), mapper);
            log.info("[KeycloakAdminApi] Updated protocol mapper '{}' on client uuid={}",
                    mapper.getName(), clientUuid);
        }
    }

    public void deleteProtocolMapper(String realmName, String clientUuid, String mapperUuid, String mapperName) {
        try (Keycloak admin = session.client()) {
            admin.realm(realmName).clients().get(clientUuid).getProtocolMappers().delete(mapperUuid);
            log.info("[KeycloakAdminApi] Deleted protocol mapper '{}' (uuid={}) from client uuid={}",
                    mapperName, mapperUuid, clientUuid);
        }
    }

    // ── Identity providers ──────────────────────────────────────────

    public List<IdentityProviderRepresentation> listIdps(String realmName) {
        try (Keycloak admin = session.client()) {
            return admin.realm(realmName).identityProviders().findAll();
        }
    }

    public Optional<IdentityProviderRepresentation> findIdp(String realmName, String alias) {
        try (Keycloak admin = session.client()) {
            return Optional.of(admin.realm(realmName).identityProviders().get(alias).toRepresentation());
        } catch (NotFoundException e) {
            return Optional.empty();
        }
    }

    public void createIdp(String realmName, IdentityProviderRepresentation idp) {
        try (Keycloak admin = session.client()) {
            admin.realm(realmName).identityProviders().create(idp);
            log.info("[KeycloakAdminApi] Created IdP '{}' ({}) in realm '{}'",
                    idp.getAlias(), idp.getProviderId(), realmName);
        }
    }

    public void updateIdp(String realmName, String alias, IdentityProviderRepresentation idp) {
        try (Keycloak admin = session.client()) {
            admin.realm(realmName).identityProviders().get(alias).update(idp);
            log.info("[KeycloakAdminApi] Updated IdP '{}' in realm '{}'", alias, realmName);
        }
    }

    // ── Realm roles ─────────────────────────────────────────────────

    public boolean realmRoleExists(String realmName, String roleName) {
        try (Keycloak admin = session.client()) {
            admin.realm(realmName).roles().get(roleName).toRepresentation();
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

    /** Look up multiple realm roles by name in one shot — the PUT roles
     *  endpoint needs {@link RoleRepresentation} objects for
     *  {@code roles().realmLevel().add/remove}. */
    public List<RoleRepresentation> findRealmRoleReps(String realmName, List<String> roleNames) {
        try (Keycloak admin = session.client()) {
            RealmResource realm = admin.realm(realmName);
            List<RoleRepresentation> out = new ArrayList<>(roleNames.size());
            for (String name : roleNames) {
                try {
                    out.add(realm.roles().get(name).toRepresentation());
                } catch (NotFoundException e) {
                    throw new NotFoundException("Realm role '" + name + "' not found in realm '" + realmName + "'");
                }
            }
            return out;
        }
    }

    // ── Users ───────────────────────────────────────────────────────

    /** Exact-email search. Keycloak's {@code search(email, ...)} matches
     *  substring; the {@code searchByEmail} variant (exact=true) is what
     *  the UserService needs to make "duplicate email" checks reliable. */
    public List<UserRepresentation> findUsersByEmail(String realmName, String email) {
        try (Keycloak admin = session.client()) {
            return admin.realm(realmName).users().searchByEmail(email, true);
        }
    }

    public Optional<UserRepresentation> findUser(String realmName, String userId) {
        try (Keycloak admin = session.client()) {
            return Optional.of(admin.realm(realmName).users().get(userId).toRepresentation());
        } catch (NotFoundException e) {
            return Optional.empty();
        }
    }

    /** @return the newly-created user's UUID. Throws with the raw HTTP
     *  status so the caller can distinguish 409 (duplicate email) from
     *  500. */
    public String createUser(String realmName, UserRepresentation user) {
        try (Keycloak admin = session.client()) {
            try (Response resp = admin.realm(realmName).users().create(user)) {
                int status = resp.getStatus();
                if (status == 201) {
                    // Keycloak returns the new id via the Location header.
                    String location = resp.getHeaderString("Location");
                    if (location == null) {
                        throw new IllegalStateException("Keycloak returned 201 without Location header");
                    }
                    String id = location.substring(location.lastIndexOf('/') + 1);
                    log.info("[KeycloakAdminApi] Created user id={} email='{}' in realm '{}'",
                            id, user.getEmail(), realmName);
                    return id;
                }
                throw new KeycloakApiException(
                        "User create failed: HTTP " + status + " body="
                                + (resp.hasEntity() ? resp.readEntity(String.class) : "<empty>"),
                        status);
            }
        }
    }

    public void updateUser(String realmName, String userId, UserRepresentation user) {
        try (Keycloak admin = session.client()) {
            admin.realm(realmName).users().get(userId).update(user);
            log.debug("[KeycloakAdminApi] Updated user id={} in realm '{}'", userId, realmName);
        }
    }

    public void deleteUser(String realmName, String userId) {
        try (Keycloak admin = session.client()) {
            admin.realm(realmName).users().get(userId).remove();
            log.info("[KeycloakAdminApi] Deleted user id={} in realm '{}'", userId, realmName);
        }
    }

    public List<RoleRepresentation> getUserRealmRoles(String realmName, String userId) {
        try (Keycloak admin = session.client()) {
            return admin.realm(realmName).users().get(userId).roles().realmLevel().listAll();
        }
    }

    public void addUserRealmRoles(String realmName, String userId, List<RoleRepresentation> roles) {
        if (roles.isEmpty()) return;
        try (Keycloak admin = session.client()) {
            admin.realm(realmName).users().get(userId).roles().realmLevel().add(roles);
        }
    }

    public void removeUserRealmRoles(String realmName, String userId, List<RoleRepresentation> roles) {
        if (roles.isEmpty()) return;
        try (Keycloak admin = session.client()) {
            admin.realm(realmName).users().get(userId).roles().realmLevel().remove(roles);
        }
    }

    /** Set a password on a user. {@code temporary=true} forces
     *  {@code UPDATE_PASSWORD} required action on next login — matches
     *  the admin-created flow. */
    public void resetPassword(String realmName, String userId, String password, boolean temporary) {
        CredentialRepresentation cred = new CredentialRepresentation();
        cred.setType(CredentialRepresentation.PASSWORD);
        cred.setValue(password);
        cred.setTemporary(temporary);
        try (Keycloak admin = session.client()) {
            UserResource userRes = admin.realm(realmName).users().get(userId);
            userRes.resetPassword(cred);
        }
    }

    /** Thrown when the Admin REST call comes back with a non-2xx we care
     *  about propagating specifically (mostly 409 on user create). */
    public static class KeycloakApiException extends RuntimeException {
        private final int status;
        public KeycloakApiException(String message, int status) {
            super(message);
            this.status = status;
        }
        public int status() { return status; }
    }
}
