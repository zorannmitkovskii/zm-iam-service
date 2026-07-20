package zm.iam.provisioning;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceContext;
import lombok.extern.slf4j.Slf4j;
import zm.iam.keycloak.KeycloakAdminApi;
import zm.iam.provisioning.dto.ClientDeclaration;
import zm.iam.provisioning.dto.ProtocolMapperDeclaration;
import zm.iam.provisioning.dto.RealmDeclaration;
import zm.iam.provisioning.dto.ServiceProvisioningManifest;
import zm.iam.provisioning.hashing.ManifestHasher;
import zm.iam.provisioning.ownership.OwnershipService;
import zm.iam.provisioning.persistence.AppliedManifest;
import zm.iam.provisioning.persistence.AppliedManifestRepository;
import zm.iam.provisioning.reconcile.ChangeEntry;
import zm.iam.provisioning.reconcile.ClientReconciler;
import zm.iam.provisioning.reconcile.IdpReconciler;
import zm.iam.provisioning.reconcile.ProtocolMapperReconciler;
import zm.iam.provisioning.reconcile.RealmReconciler;
import zm.iam.provisioning.reconcile.RoleReconciler;
import zm.iam.audit.AuditEvent;
import zm.iam.audit.AuditService;
import zm.iam.audit.TargetType;
import zm.iam.security.internal.OwnedRealmsCache;
import org.keycloak.representations.idm.ClientRepresentation;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.OffsetDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;

/**
 * The engine. Every apply runs inside a single Postgres transaction so
 * the {@code pg_advisory_xact_lock} is released automatically on
 * commit/rollback — no manual unlock, no leaked locks on JVM crashes.
 * A reconciler failure rolls the whole thing back: the
 * {@code applied_manifests} row is NOT written, and a retry with the
 * same version after fixing the root cause is safe.
 *
 * <p>Per-realm reconciler order: realm → clients (client fields, then
 * mappers) → roles → idps. The mapper reconciler needs the previous
 * applied manifest to decide safe deletes; we deserialise that manifest
 * once up-front.
 */
@Slf4j
@Service
public class ProvisioningService {

    private final AppliedManifestRepository repository;
    private final ManifestHasher hasher;
    private final ObjectMapper canonicalMapper;
    private final KeycloakAdminApi keycloak;
    private final OwnershipService ownership;
    private final RealmReconciler realmReconciler;
    private final ClientReconciler clientReconciler;
    private final ProtocolMapperReconciler mapperReconciler;
    private final RoleReconciler roleReconciler;
    private final IdpReconciler idpReconciler;
    private final AuditService audit;

    /** Optional so tests that don't wire the security package (e.g.
     *  pure reconciler slice tests) still compile. Runtime always has
     *  one — the bean is unconditionally registered by SecurityConfig. */
    @Autowired(required = false)
    private OwnedRealmsCache ownedRealmsCache;

    @PersistenceContext
    private EntityManager em;

    public ProvisioningService(AppliedManifestRepository repository,
                               ManifestHasher hasher,
                               @Qualifier("manifestCanonicalMapper") ObjectMapper canonicalMapper,
                               KeycloakAdminApi keycloak,
                               OwnershipService ownership,
                               RealmReconciler realmReconciler,
                               ClientReconciler clientReconciler,
                               ProtocolMapperReconciler mapperReconciler,
                               RoleReconciler roleReconciler,
                               IdpReconciler idpReconciler,
                               AuditService audit) {
        this.repository = repository;
        this.hasher = hasher;
        this.canonicalMapper = canonicalMapper;
        this.keycloak = keycloak;
        this.ownership = ownership;
        this.realmReconciler = realmReconciler;
        this.clientReconciler = clientReconciler;
        this.mapperReconciler = mapperReconciler;
        this.roleReconciler = roleReconciler;
        this.idpReconciler = idpReconciler;
        this.audit = audit;
    }

    @Transactional
    public ApplyResult apply(ServiceProvisioningManifest manifest) {
        Optional<AppliedManifest> latest = repository.findFirstByServiceIdOrderByVersionDesc(manifest.serviceId());

        // ── Version gate ────────────────────────────────────────────
        if (latest.isPresent() && manifest.manifestVersion() <= latest.get().getVersion()) {
            AppliedManifest prev = latest.get();
            String incomingHash = hasher.hash(manifest);
            if (manifest.manifestVersion() == prev.getVersion() && !prev.getManifestHash().equals(incomingHash)) {
                throw new IllegalStateException(
                        "Manifest version " + manifest.manifestVersion() + " for '" + manifest.serviceId()
                                + "' was already applied with a different body — bump the version to change it.");
            }
            log.info("[Provisioning] NOOP for serviceId='{}' — incoming version {} <= applied {}",
                    manifest.serviceId(), manifest.manifestVersion(), prev.getVersion());
            audit.record(AuditEvent.builder()
                    .caller(manifest.serviceId())
                    .targetType(TargetType.MANIFEST)
                    .targetId(manifest.serviceId() + ":v" + manifest.manifestVersion())
                    .operation("NOOP")
                    .detail(java.util.Map.of("appliedVersion", prev.getVersion()))
                    .success(true)
                    .build());
            return new ApplyResult(ApplyResult.Status.NOOP, manifest.serviceId(), prev.getVersion(), List.of());
        }

        // ── Ownership pre-check (IAM-06) ───────────────────────────
        // Read-only. Throws OwnershipConflictException BEFORE any
        // Keycloak write, so a conflict leaves Keycloak untouched.
        ownership.check(manifest.serviceId(), manifest);

        // Deserialise previous manifest once — mapper reconciler needs it
        // for the "only delete what we planted" decision.
        ServiceProvisioningManifest previousManifest = latest.map(this::deserialise).orElse(null);

        // ── Reconcile per realm under advisory lock ────────────────
        List<ChangeEntry> appliedSteps = new ArrayList<>();
        try {
            for (RealmDeclaration realm : manifest.realms()) {
                acquireRealmLock(realm.name());
                appliedSteps.addAll(realmReconciler.reconcile(realm));

                if (realm.clients() != null) {
                    for (ClientDeclaration clientDecl : realm.clients()) {
                        appliedSteps.addAll(clientReconciler.reconcile(realm.name(), clientDecl));
                        // Fetch the (now-existing) client UUID for mapper attach.
                        Optional<ClientRepresentation> current =
                                keycloak.findClient(realm.name(), clientDecl.clientId());
                        if (current.isPresent()) {
                            List<ProtocolMapperDeclaration> prevMappers =
                                    previousMappersFor(previousManifest, realm.name(), clientDecl.clientId());
                            appliedSteps.addAll(mapperReconciler.reconcile(
                                    realm.name(), current.get().getId(),
                                    clientDecl, clientDecl.protocolMappers(), prevMappers));
                        }
                    }
                }
                appliedSteps.addAll(roleReconciler.reconcile(realm.name(), realm.realmRoles()));
                appliedSteps.addAll(idpReconciler.reconcile(realm.name(), realm.identityProviders()));
            }
        } catch (RuntimeException e) {
            log.error("[Provisioning] Apply FAILED for serviceId='{}' version={} after {} step(s): {}",
                    manifest.serviceId(), manifest.manifestVersion(), appliedSteps.size(), e.getMessage());
            throw new ProvisioningFailedException(
                    "Provisioning failed: " + e.getMessage(), appliedSteps, e);
        }

        // ── Register ownership rows (IAM-06) ───────────────────────
        // Idempotent — resources we already own are no-ops.
        ownership.register(manifest.serviceId(), manifest);

        // ── Persist AppliedManifest — commit == permanence ─────────
        AppliedManifest record = AppliedManifest.builder()
                .serviceId(manifest.serviceId())
                .version(manifest.manifestVersion())
                .manifestHash(hasher.hash(manifest))
                .manifestJson(toJsonNode(manifest))
                .changes(toJsonNode(appliedSteps))
                .appliedAt(OffsetDateTime.now())
                .build();
        repository.save(record);

        // ── IAM-09 cache invalidation ──────────────────────────────
        // Ownership rows just changed (new realms owned, or a first-
        // time owner planted). The realm-scope authz filter caches
        // the "serviceId → owned realms" mapping in memory, so evict
        // the entry for this service to force a re-read on the next
        // /internal/** call. Guarded — the cache bean may be null in
        // slice tests that don't load the security package.
        if (ownedRealmsCache != null) {
            ownedRealmsCache.invalidate(manifest.serviceId());
        }

        log.info("[Provisioning] APPLIED serviceId='{}' version={} with {} changes",
                manifest.serviceId(), manifest.manifestVersion(), appliedSteps.size());

        // ── IAM-11 audit — one row per apply, count-only detail so
        //    values like redirect URIs never land in the audit table.
        audit.record(AuditEvent.builder()
                .caller(manifest.serviceId())
                .targetType(TargetType.MANIFEST)
                .targetId(manifest.serviceId() + ":v" + manifest.manifestVersion())
                .operation("APPLY")
                .detail(java.util.Map.of(
                        "manifestHash", record.getManifestHash(),
                        "changeCount", appliedSteps.size()))
                .success(true)
                .build());

        return new ApplyResult(ApplyResult.Status.APPLIED, manifest.serviceId(),
                manifest.manifestVersion(), appliedSteps);
    }

    // ── helpers ────────────────────────────────────────────────────

    private void acquireRealmLock(String realmName) {
        em.createNativeQuery("SELECT pg_advisory_xact_lock(hashtext(:name))")
                .setParameter("name", realmName)
                .getSingleResult();
    }

    private ServiceProvisioningManifest deserialise(AppliedManifest row) {
        try {
            return canonicalMapper.treeToValue(row.getManifestJson(), ServiceProvisioningManifest.class);
        } catch (Exception e) {
            log.warn("Could not deserialise previous manifest for '{}' v{} — treating as empty",
                    row.getServiceId(), row.getVersion(), e);
            return null;
        }
    }

    private static List<ProtocolMapperDeclaration> previousMappersFor(
            ServiceProvisioningManifest previous, String realmName, String clientId) {
        if (previous == null || previous.realms() == null) return List.of();
        Map<String, RealmDeclaration> prevRealms = previous.realms().stream()
                .collect(Collectors.toMap(RealmDeclaration::name, r -> r, (a, b) -> a));
        RealmDeclaration prevRealm = prevRealms.get(realmName);
        if (prevRealm == null || prevRealm.clients() == null) return List.of();
        for (ClientDeclaration c : prevRealm.clients()) {
            if (clientId.equals(c.clientId())) {
                return c.protocolMappers() == null ? List.of() : c.protocolMappers();
            }
        }
        return List.of();
    }

    private JsonNode toJsonNode(Object value) {
        return canonicalMapper.valueToTree(value);
    }
}
