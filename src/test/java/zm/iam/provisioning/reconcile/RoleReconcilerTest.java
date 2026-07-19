package zm.iam.provisioning.reconcile;

import zm.iam.keycloak.KeycloakAdminApi;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class RoleReconcilerTest {

    @Test
    @DisplayName("Missing role → CREATED; existing role → SKIPPED; never DELETED")
    void createsMissingSkipsExisting() {
        KeycloakAdminApi api = mock(KeycloakAdminApi.class);
        when(api.realmRoleExists("app", "USER")).thenReturn(false);
        when(api.realmRoleExists("app", "ADMIN")).thenReturn(true);

        List<ChangeEntry> changes = new RoleReconciler(api).reconcile("app", List.of("USER", "ADMIN"));

        verify(api).createRealmRole(eq("app"), eq("USER"), any());
        verify(api, never()).createRealmRole(eq("app"), eq("ADMIN"), any());
        assertThat(changes).extracting(ChangeEntry::action).containsExactly("CREATED", "SKIPPED");
    }

    @Test
    @DisplayName("Null / empty declared list → no-op")
    void nullListIsNoop() {
        KeycloakAdminApi api = mock(KeycloakAdminApi.class);
        assertThat(new RoleReconciler(api).reconcile("app", null)).isEmpty();
        assertThat(new RoleReconciler(api).reconcile("app", List.of())).isEmpty();
    }
}
