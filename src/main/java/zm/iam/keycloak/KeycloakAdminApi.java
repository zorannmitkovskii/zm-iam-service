package zm.iam.keycloak;

import jakarta.ws.rs.NotFoundException;
import lombok.extern.slf4j.Slf4j;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.resource.ClientResource;
import org.keycloak.admin.client.resource.RealmResource;
import org.keycloak.representations.idm.ClientRepresentation;
import org.keycloak.representations.idm.IdentityProviderRepresentation;
import org.keycloak.representations.idm.ProtocolMapperRepresentation;
import org.keycloak.representations.idm.RealmRepresentation;
import org.keycloak.representations.idm.RoleRepresentation;
import org.springframework.stereotype.Component;

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
}
