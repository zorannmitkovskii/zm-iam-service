package zm.iam.provisioning.reconcile;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import zm.iam.keycloak.KeycloakAdminApi;
import zm.iam.provisioning.dto.ClientDeclaration;
import zm.iam.provisioning.dto.ClientType;

import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class ServiceAccountRoleReconcilerTest {

    private static final String REALM = "zm-services";
    private static final String CLIENT = "zm-menu-service-svc";
    private static final String SERVICE_ACCOUNT_USER = "user-uuid";

    private KeycloakAdminApi keycloak;
    private ServiceAccountRoleReconciler reconciler;

    private static ClientDeclaration declaring(List<String> roles) {
        return new ClientDeclaration(CLIENT, ClientType.CONFIDENTIAL, null, null, null,
                true, null, roles, null);
    }

    @BeforeEach
    void setUp() {
        keycloak = mock(KeycloakAdminApi.class);
        reconciler = new ServiceAccountRoleReconciler(keycloak);
        when(keycloak.findServiceAccountUserId(REALM, CLIENT))
                .thenReturn(Optional.of(SERVICE_ACCOUNT_USER));
        when(keycloak.userRealmRoleNames(REALM, SERVICE_ACCOUNT_USER)).thenReturn(List.of());
        when(keycloak.realmRoleExists(eq(REALM), anyString())).thenReturn(true);
    }

    @Test
    @DisplayName("Declared roles are granted to the service account user")
    void grantsDeclaredRoles() {
        List<ChangeEntry> changes = reconciler.reconcile(REALM, declaring(List.of("iam-client", "org-client")));

        verify(keycloak).addUserRealmRoles(REALM, SERVICE_ACCOUNT_USER, List.of("iam-client", "org-client"));
        assertThat(changes).extracting(ChangeEntry::action).containsOnly("CREATED");
    }

    @Test
    @DisplayName("A role the account already holds is skipped, not re-granted")
    void alreadyHeldRoleIsSkipped() {
        when(keycloak.userRealmRoleNames(REALM, SERVICE_ACCOUNT_USER)).thenReturn(List.of("iam-client"));

        List<ChangeEntry> changes = reconciler.reconcile(REALM, declaring(List.of("iam-client")));

        verify(keycloak, never()).addUserRealmRoles(anyString(), anyString(), any());
        assertThat(changes).singleElement()
                .extracting(ChangeEntry::action).isEqualTo("SKIPPED");
    }

    @Test
    @DisplayName("A role owned by a manifest that has not been applied yet is reported, not fatal")
    void missingRoleIsReportedNotFatal() {
        when(keycloak.realmRoleExists(REALM, "org-client")).thenReturn(false);

        List<ChangeEntry> changes = reconciler.reconcile(REALM, declaring(List.of("iam-client", "org-client")));

        verify(keycloak).addUserRealmRoles(REALM, SERVICE_ACCOUNT_USER, List.of("iam-client"));
        assertThat(changes).hasSize(2);
        assertThat(changes).anySatisfy(change -> {
            assertThat(change.name()).endsWith("org-client");
            assertThat(change.action()).isEqualTo("SKIPPED");
            assertThat(change.details()).contains("does not exist yet");
        });
    }

    @Test
    @DisplayName("Declaring roles on a client with no service account is reported plainly")
    void clientWithoutServiceAccountIsReported() {
        when(keycloak.findServiceAccountUserId(REALM, CLIENT)).thenReturn(Optional.empty());

        List<ChangeEntry> changes = reconciler.reconcile(REALM, declaring(List.of("iam-client")));

        verify(keycloak, never()).addUserRealmRoles(anyString(), anyString(), any());
        assertThat(changes).singleElement().satisfies(change -> {
            assertThat(change.action()).isEqualTo("SKIPPED");
            assertThat(change.details()).contains("serviceAccountsEnabled");
        });
    }

    @Test
    @DisplayName("A client declaring no roles produces no changes and no Keycloak calls")
    void noDeclaredRolesIsANoOp() {
        assertThat(reconciler.reconcile(REALM, declaring(null))).isEmpty();
        assertThat(reconciler.reconcile(REALM, declaring(List.of()))).isEmpty();

        verify(keycloak, never()).findServiceAccountUserId(anyString(), anyString());
    }
}
