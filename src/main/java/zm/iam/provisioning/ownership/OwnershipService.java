package zm.iam.provisioning.ownership;

import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import zm.iam.provisioning.dto.ClientDeclaration;
import zm.iam.provisioning.dto.IdentityProviderDeclaration;
import zm.iam.provisioning.dto.RealmDeclaration;
import zm.iam.provisioning.dto.ServiceProvisioningManifest;

import java.time.OffsetDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

/**
 * Ownership policy engine:
 * <ul>
 *   <li>{@link #check(String, ServiceProvisioningManifest)} — read-only,
 *       throws {@link OwnershipConflictException} if the caller touches
 *       any resource owned by another service. Runs BEFORE any Keycloak
 *       write so a conflict leaves Keycloak untouched.</li>
 *   <li>{@link #register(String, ServiceProvisioningManifest)} —
 *       idempotent upsert of ownership rows for every resource the
 *       manifest declared. Called AFTER a successful reconciler chain
 *       inside the same transaction.</li>
 *   <li>{@link #registerBootstrap(String, String, ResourceType)} —
 *       used by {@link zm.iam.keycloak.bootstrap.ServiceRealmProvisioner}
 *       to plant the {@code iam} owner of {@code zm-services} at
 *       startup.</li>
 * </ul>
 *
 * <p>Special case for {@code zm-services}: the realm itself is owned by
 * IAM (planted at bootstrap). Other services may create their own
 * {@code {serviceId}-svc} client inside it — client-level ownership is
 * tracked normally. IdPs are not permitted in {@code zm-services}
 * (schema rule from IAM-03; ownership skips them here defensively).
 */
@Slf4j
@Service
public class OwnershipService {

    static final String ZM_SERVICES_REALM = ServiceProvisioningManifest.ZM_SERVICES_REALM;
    public static final String IAM_OWNER = "iam";

    private final ResourceOwnershipRepository repository;

    public OwnershipService(ResourceOwnershipRepository repository) {
        this.repository = repository;
    }

    /** Pre-flight ownership audit. Reports every conflict at once so the
     *  operator fixes the manifest in one pass. */
    public void check(String serviceId, ServiceProvisioningManifest manifest) {
        List<OwnershipConflict> conflicts = new ArrayList<>();
        for (RealmDeclaration realm : manifest.realms()) {
            boolean isZmServices = ZM_SERVICES_REALM.equals(realm.name());
            if (!isZmServices) {
                checkOwner(ResourceType.REALM, realm.name(), realm.name(), serviceId, conflicts);
            }
            if (realm.clients() != null) {
                for (ClientDeclaration client : realm.clients()) {
                    checkOwner(ResourceType.CLIENT, realm.name(), client.clientId(), serviceId, conflicts);
                }
            }
            if (!isZmServices && realm.identityProviders() != null) {
                for (IdentityProviderDeclaration idp : realm.identityProviders()) {
                    checkOwner(ResourceType.IDP, realm.name(), idp.alias(), serviceId, conflicts);
                }
            }
        }
        if (!conflicts.isEmpty()) {
            log.warn("[Ownership] {} conflict(s) blocking serviceId='{}'", conflicts.size(), serviceId);
            throw new OwnershipConflictException(conflicts);
        }
    }

    /** Idempotent upsert. Realm-level rows are only written for realms we
     *  own (skip zm-services — IAM's bootstrap seeded it). Client + IdP
     *  rows are always attempted; {@code createIfMissing} short-circuits
     *  duplicates. */
    public void register(String serviceId, ServiceProvisioningManifest manifest) {
        for (RealmDeclaration realm : manifest.realms()) {
            boolean isZmServices = ZM_SERVICES_REALM.equals(realm.name());
            if (!isZmServices) {
                createIfMissing(ResourceType.REALM, realm.name(), realm.name(), serviceId);
            }
            if (realm.clients() != null) {
                for (ClientDeclaration client : realm.clients()) {
                    createIfMissing(ResourceType.CLIENT, realm.name(), client.clientId(), serviceId);
                }
            }
            if (!isZmServices && realm.identityProviders() != null) {
                for (IdentityProviderDeclaration idp : realm.identityProviders()) {
                    createIfMissing(ResourceType.IDP, realm.name(), idp.alias(), serviceId);
                }
            }
        }
    }

    /** ServiceRealmProvisioner uses this to plant IAM as owner of the
     *  shared {@code zm-services} realm at startup. */
    public void registerBootstrap(String realm, String resourceName, ResourceType type) {
        createIfMissing(type, realm, resourceName, IAM_OWNER);
    }

    // ── helpers ────────────────────────────────────────────────────

    private void checkOwner(ResourceType type, String realm, String resource,
                            String serviceId, List<OwnershipConflict> conflicts) {
        Optional<ResourceOwnership> existing =
                repository.findByResourceTypeAndRealmAndResourceName(type, realm, resource);
        if (existing.isEmpty()) return;
        if (existing.get().getOwnerService().equals(serviceId)) return;
        conflicts.add(new OwnershipConflict(
                type, realm, resource, existing.get().getOwnerService(),
                type.name() + " '" + resource + "' in realm '" + realm
                        + "' is owned by '" + existing.get().getOwnerService()
                        + "' — service '" + serviceId + "' cannot modify it."));
    }

    private void createIfMissing(ResourceType type, String realm, String resource, String owner) {
        Optional<ResourceOwnership> existing =
                repository.findByResourceTypeAndRealmAndResourceName(type, realm, resource);
        if (existing.isPresent()) return;
        repository.save(ResourceOwnership.builder()
                .resourceType(type)
                .realm(realm)
                .resourceName(resource)
                .ownerService(owner)
                .createdAt(OffsetDateTime.now())
                .build());
        log.debug("[Ownership] Registered {} '{}' in realm '{}' → owner='{}'", type, resource, realm, owner);
    }
}
