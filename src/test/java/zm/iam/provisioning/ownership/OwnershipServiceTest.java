package zm.iam.provisioning.ownership;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import zm.iam.provisioning.dto.ClientDeclaration;
import zm.iam.provisioning.dto.ClientType;
import zm.iam.provisioning.dto.IdentityProviderDeclaration;
import zm.iam.provisioning.dto.RealmDeclaration;
import zm.iam.provisioning.dto.ServiceProvisioningManifest;

import java.time.OffsetDateTime;
import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Table-driven coverage of the ownership rules. Backing repo is mocked
 * so we can express every AC as a small "given the DB says X" scenario.
 */
class OwnershipServiceTest {

    private ResourceOwnershipRepository repo;
    private OwnershipService service;

    @BeforeEach
    void setUp() {
        repo = mock(ResourceOwnershipRepository.class);
        service = new OwnershipService(repo);
    }

    // ── AC 1 — foreign realm blocks apply ────────────────────────

    @Test
    @DisplayName("Foreign realm owner → OwnershipConflictException, register never called")
    void foreignRealmConflict() {
        when(repo.findByResourceTypeAndRealmAndResourceName(
                ResourceType.REALM, "event-app", "event-app"))
                .thenReturn(Optional.of(ownership(ResourceType.REALM, "event-app", "event-app", "service-a")));

        var manifest = manifest("service-b", 1, realm("event-app", null, null));

        assertThatThrownBy(() -> service.check("service-b", manifest))
                .isInstanceOf(OwnershipConflictException.class)
                .satisfies(ex -> {
                    var conflict = ((OwnershipConflictException) ex).getConflicts().get(0);
                    assertThat(conflict.conflictType()).isEqualTo(ResourceType.REALM);
                    assertThat(conflict.ownerService()).isEqualTo("service-a");
                });
    }

    // ── AC 2 — different realms per service both go through ─────

    @Test
    @DisplayName("Own realm passes check, register called for realm + client")
    void ownRealmPassesAndRegisters() {
        when(repo.findByResourceTypeAndRealmAndResourceName(any(), any(), any()))
                .thenReturn(Optional.empty());

        var manifest = manifest("service-a", 1, realm("event-app", List.of(
                new ClientDeclaration("eventFE", ClientType.PUBLIC, null, null, null, null, null, null, null, null)),
                null));

        service.check("service-a", manifest);
        service.register("service-a", manifest);

        verify(repo, atLeastOnce()).save(any());  // realm + client both saved
    }

    // ── AC 4 — zm-services special: realm-level check skipped ───

    @Test
    @DisplayName("zm-services realm-level ownership check is skipped; client-level still enforced")
    void zmServicesRealmCheckSkipped() {
        // The realm-level lookup for zm-services should NEVER be issued.
        var manifest = new ServiceProvisioningManifest("ivy-events-be", 1, List.of(
                new RealmDeclaration("zm-services", null,
                        List.of(new ClientDeclaration("ivy-events-be-svc", ClientType.CONFIDENTIAL,
                                null, null, null, true, null, null, List.of("iam-client"), null)),
                        null, null, null)));

        when(repo.findByResourceTypeAndRealmAndResourceName(any(), any(), any()))
                .thenReturn(Optional.empty());

        service.check("ivy-events-be", manifest);

        verify(repo, never()).findByResourceTypeAndRealmAndResourceName(
                eq(ResourceType.REALM), eq("zm-services"), any());
        verify(repo).findByResourceTypeAndRealmAndResourceName(
                ResourceType.CLIENT, "zm-services", "ivy-events-be-svc");
    }

    // ── AC 6 — same service re-declaring own resource → no conflict, no duplicate ──

    @Test
    @DisplayName("Same service re-declaring own resource → check passes, register no-ops (row exists)")
    void reDeclarationIsIdempotent() {
        when(repo.findByResourceTypeAndRealmAndResourceName(
                ResourceType.REALM, "event-app", "event-app"))
                .thenReturn(Optional.of(ownership(ResourceType.REALM, "event-app", "event-app", "service-a")));

        var manifest = manifest("service-a", 2, realm("event-app", null, null));

        service.check("service-a", manifest);
        service.register("service-a", manifest);

        // Register must NOT save a duplicate — the row already exists.
        verify(repo, never()).save(any());
    }

    // ── AC 3 — roles are not tracked ─────────────────────────────

    @Test
    @DisplayName("Roles never touch the ownership table")
    void rolesAreNotTracked() {
        when(repo.findByResourceTypeAndRealmAndResourceName(any(), any(), any()))
                .thenReturn(Optional.empty());

        var manifest = manifest("service-a", 1,
                new RealmDeclaration("event-app", null, null,
                        List.of("USER", "ADMIN"), null, null));

        service.check("service-a", manifest);
        service.register("service-a", manifest);

        // Only realm row saved (no roles).
        verify(repo, never()).findByResourceTypeAndRealmAndResourceName(
                any(), eq("event-app"), eq("USER"));
    }

    // ── Foreign IdP also blocks ──────────────────────────────────

    @Test
    @DisplayName("Foreign IdP owner → conflict")
    void foreignIdpConflict() {
        when(repo.findByResourceTypeAndRealmAndResourceName(
                ResourceType.REALM, "event-app", "event-app"))
                .thenReturn(Optional.empty());
        when(repo.findByResourceTypeAndRealmAndResourceName(
                ResourceType.IDP, "event-app", "google"))
                .thenReturn(Optional.of(ownership(ResourceType.IDP, "event-app", "google", "service-a")));

        var manifest = manifest("service-b", 1, new RealmDeclaration(
                "event-app", null, null, null,
                List.of(new IdentityProviderDeclaration("google", "GOOGLE", "MY_ID", "MY_SECRET")),
                null));

        assertThatThrownBy(() -> service.check("service-b", manifest))
                .isInstanceOf(OwnershipConflictException.class);
    }

    // ── helpers ──────────────────────────────────────────────────

    private static ResourceOwnership ownership(ResourceType type, String realm, String name, String owner) {
        return ResourceOwnership.builder()
                .resourceType(type)
                .realm(realm)
                .resourceName(name)
                .ownerService(owner)
                .createdAt(OffsetDateTime.now())
                .build();
    }

    private static ServiceProvisioningManifest manifest(String svc, int version, RealmDeclaration... realms) {
        return new ServiceProvisioningManifest(svc, version, List.of(realms));
    }

    private static RealmDeclaration realm(String name, List<ClientDeclaration> clients,
                                           List<IdentityProviderDeclaration> idps) {
        return new RealmDeclaration(name, null, clients, null, idps, null);
    }
}
