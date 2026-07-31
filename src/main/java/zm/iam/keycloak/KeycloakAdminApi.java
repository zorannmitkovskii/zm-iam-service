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
import java.util.HashMap;
import java.util.List;
import java.util.Map;
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

    /** Realm role names already granted to a user, realm-level only. */
    public List<String> userRealmRoleNames(String realmName, String userId) {
        try (Keycloak admin = session.client()) {
            return admin.realm(realmName).users().get(userId)
                    .roles().realmLevel().listEffective().stream()
                    .map(RoleRepresentation::getName)
                    .toList();
        }
    }

    /**
     * The user Keycloak creates behind a client with service accounts enabled.
     * Realm roles are granted to that user, not to the client, which is why
     * assigning a service account role needs this indirection.
     */
    public Optional<String> findServiceAccountUserId(String realmName, String clientId) {
        try (Keycloak admin = session.client()) {
            Optional<ClientRepresentation> client = admin.realm(realmName)
                    .clients().findByClientId(clientId).stream().findFirst();
            if (client.isEmpty()) {
                return Optional.empty();
            }
            UserRepresentation serviceAccount = admin.realm(realmName)
                    .clients().get(client.get().getId()).getServiceAccountUser();
            return Optional.ofNullable(serviceAccount).map(UserRepresentation::getId);
        } catch (NotFoundException e) {
            return Optional.empty();
        }
    }

    // ── IAM-10 user operations ──────────────────────────────────────

    /** Exact-email search inside a realm. Returns empty when not found. */
    public Optional<UserRepresentation> findUserByEmail(String realmName, String email) {
        try (Keycloak admin = session.client()) {
            List<UserRepresentation> hits = admin.realm(realmName).users().searchByEmail(email, true);
            return hits.isEmpty() ? Optional.empty() : Optional.of(hits.get(0));
        }
    }

    /** Create a disabled user (public register flow enables it after
     *  email verification). Returns the Keycloak UUID. */
    public String createUser(String realmName, String email, String firstName, String lastName,
                              boolean enabled) {
        UserRepresentation user = new UserRepresentation();
        user.setEmail(email);
        user.setUsername(email);
        user.setFirstName(firstName);
        user.setLastName(lastName);
        user.setEnabled(enabled);
        user.setEmailVerified(false);
        try (Keycloak admin = session.client();
             Response resp = admin.realm(realmName).users().create(user)) {
            if (resp.getStatus() == 201) {
                String location = resp.getHeaderString("Location");
                String id = location.substring(location.lastIndexOf('/') + 1);
                log.info("[KeycloakAdminApi] Created user id={} email='{}' in realm '{}' (enabled={})",
                        id, email, realmName, enabled);
                return id;
            }
            throw new KeycloakApiException(
                    "User create failed: HTTP " + resp.getStatus() + " body="
                            + (resp.hasEntity() ? resp.readEntity(String.class) : "<empty>"),
                    resp.getStatus());
        }
    }

    /** Toggle user enable/disable — post-verification flip and
     *  admin-side user management alike use this. */
    public void setUserEnabled(String realmName, String userId, boolean enabled) {
        try (Keycloak admin = session.client()) {
            UserRepresentation user = admin.realm(realmName).users().get(userId).toRepresentation();
            user.setEnabled(enabled);
            if (enabled) user.setEmailVerified(true);
            admin.realm(realmName).users().get(userId).update(user);
            log.info("[KeycloakAdminApi] User id={} enabled={} in realm '{}'", userId, enabled, realmName);
        }
    }

    /** Reset a user's password. {@code temporary=false} for public
     *  self-serve flows (register verification, password reset);
     *  {@code true} for admin-provisioned accounts that must change on
     *  first login. */
    public void resetUserPassword(String realmName, String userId, String newPassword, boolean temporary) {
        CredentialRepresentation cred = new CredentialRepresentation();
        cred.setType(CredentialRepresentation.PASSWORD);
        cred.setValue(newPassword);
        cred.setTemporary(temporary);
        try (Keycloak admin = session.client()) {
            admin.realm(realmName).users().get(userId).resetPassword(cred);
            log.info("[KeycloakAdminApi] Reset password for user id={} realm='{}' (temporary={})",
                    userId, realmName, temporary);
        }
    }

    /**
     * Applies set → append → remove to a user's attributes in that order, and
     * returns the user as it now stands.
     *
     * <p>Append is what Ivy needs on every event creation: one more id in
     * {@code eventIds}, without knowing or clobbering what is already there.
     * Reading, merging and writing in one call is what keeps two events
     * created at the same time from erasing each other — the read-modify-write
     * a caller would otherwise do outside this method has no such protection.
     *
     * <p>Appending a value that is already present is a no-op rather than a
     * duplicate: the attribute is a set of ids in all but name, and a token
     * carrying the same event twice helps nobody.
     */
    public UserRepresentation patchUserAttributes(String realmName, String userId,
                                                   Map<String, List<String>> set,
                                                   Map<String, List<String>> append,
                                                   Map<String, List<String>> remove) {
        try (Keycloak admin = session.client()) {
            UserResource resource = admin.realm(realmName).users().get(userId);
            UserRepresentation user = resource.toRepresentation();

            Map<String, List<String>> attributes = user.getAttributes() == null
                    ? new HashMap<>()
                    : new HashMap<>(user.getAttributes());

            if (set != null) {
                set.forEach((key, values) -> attributes.put(key, new ArrayList<>(values)));
            }
            if (append != null) {
                append.forEach((key, values) -> {
                    List<String> current = new ArrayList<>(
                            attributes.getOrDefault(key, List.of()));
                    values.stream().filter(v -> !current.contains(v)).forEach(current::add);
                    attributes.put(key, current);
                });
            }
            if (remove != null) {
                remove.forEach((key, values) -> {
                    List<String> current = new ArrayList<>(
                            attributes.getOrDefault(key, List.of()));
                    current.removeAll(values);
                    if (current.isEmpty()) {
                        attributes.remove(key);
                    } else {
                        attributes.put(key, current);
                    }
                });
            }

            user.setAttributes(attributes);
            resource.update(user);
            log.info("[KeycloakAdminApi] Patched attributes for user id={} realm='{}' keys={}",
                    userId, realmName, attributes.keySet());
            return resource.toRepresentation();
        }
    }

    /** Drop a single user attribute. A user who has no such attribute is
     *  left untouched — callers use this to clear a one-shot flag
     *  ({@code mustChangePassword}) and must not care whether it was set. */
    public void removeUserAttribute(String realmName, String userId, String key) {
        try (Keycloak admin = session.client()) {
            UserResource resource = admin.realm(realmName).users().get(userId);
            UserRepresentation user = resource.toRepresentation();
            Map<String, List<String>> attributes = user.getAttributes();
            if (attributes == null || !attributes.containsKey(key)) return;
            // toRepresentation may hand back an immutable map.
            Map<String, List<String>> copy = new HashMap<>(attributes);
            copy.remove(key);
            user.setAttributes(copy);
            resource.update(user);
            log.info("[KeycloakAdminApi] Removed attribute '{}' from user id={} realm='{}'",
                    key, userId, realmName);
        }
    }

    /** Assign realm-level roles to a user by role name. */
    public void addUserRealmRoles(String realmName, String userId, List<String> roleNames) {
        if (roleNames == null || roleNames.isEmpty()) return;
        try (Keycloak admin = session.client()) {
            RealmResource realm = admin.realm(realmName);
            List<RoleRepresentation> roles = roleNames.stream()
                    .map(name -> realm.roles().get(name).toRepresentation())
                    .toList();
            realm.users().get(userId).roles().realmLevel().add(roles);
            log.info("[KeycloakAdminApi] Assigned roles {} to user id={} realm='{}'",
                    roleNames, userId, realmName);
        }
    }
}
