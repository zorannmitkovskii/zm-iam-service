package zm.iam.provisioning.reconcile;

import zm.iam.keycloak.KeycloakAdminApi;
import zm.iam.provisioning.dto.RealmDeclaration;
import zm.iam.provisioning.dto.RealmSettings;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.keycloak.representations.idm.RealmRepresentation;

import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class RealmReconcilerTest {

    private KeycloakAdminApi api;
    private RealmReconciler reconciler;

    @BeforeEach
    void setUp() {
        api = mock(KeycloakAdminApi.class);
        reconciler = new RealmReconciler(api);
    }

    @Test
    @DisplayName("Missing realm → CREATE with declared settings")
    void createsMissingRealm() {
        when(api.findRealm("app")).thenReturn(Optional.empty());

        List<ChangeEntry> changes = reconciler.reconcile(new RealmDeclaration(
                "app",
                new RealmSettings(true, false, null, null, null, null, null),
                null, null, null, null));

        verify(api).createRealm(any(RealmRepresentation.class));
        assertThat(changes).hasSize(1);
        assertThat(changes.get(0).action()).isEqualTo("CREATED");
    }

    @Test
    @DisplayName("Existing realm, all declared settings match → SKIPPED (no update call)")
    void skipsWhenAlreadyMatches() {
        RealmRepresentation existing = new RealmRepresentation();
        existing.setLoginWithEmailAllowed(true);
        existing.setRegistrationAllowed(false);
        when(api.findRealm("app")).thenReturn(Optional.of(existing));

        List<ChangeEntry> changes = reconciler.reconcile(new RealmDeclaration(
                "app",
                new RealmSettings(true, false, null, null, null, null, null),
                null, null, null, null));

        verify(api, never()).updateRealm(any(), any());
        assertThat(changes.get(0).action()).isEqualTo("SKIPPED");
    }

    @Test
    @DisplayName("Existing realm, one field differs → UPDATE with only that field in details")
    void updatesOnlyDifferingFields() {
        RealmRepresentation existing = new RealmRepresentation();
        existing.setLoginWithEmailAllowed(false);  // differs
        existing.setRegistrationAllowed(false);    // matches
        when(api.findRealm("app")).thenReturn(Optional.of(existing));

        List<ChangeEntry> changes = reconciler.reconcile(new RealmDeclaration(
                "app",
                new RealmSettings(true, false, null, null, null, null, null),
                null, null, null, null));

        verify(api, times(1)).updateRealm(eq("app"), any());
        assertThat(changes.get(0).action()).isEqualTo("UPDATED");
        assertThat(changes.get(0).details()).contains("loginWithEmailAllowed");
    }

    @Test
    @DisplayName("Undeclared (null) settings never appear in diff — additive semantics")
    void undeclaredSettingsAreAdditive() {
        RealmRepresentation existing = new RealmRepresentation();
        existing.setResetPasswordAllowed(true);
        when(api.findRealm("app")).thenReturn(Optional.of(existing));

        List<ChangeEntry> changes = reconciler.reconcile(new RealmDeclaration(
                "app",
                new RealmSettings(true, null, null, null, null, null, null),  // only loginWithEmailAllowed declared
                null, null, null, null));

        assertThat(changes.get(0).details()).doesNotContain("resetPasswordAllowed");
    }

    @Test
    @DisplayName("Session lifespans differing from Keycloak's → UPDATE that writes both")
    void updatesSessionLifespans() {
        RealmRepresentation existing = new RealmRepresentation();
        existing.setSsoSessionIdleTimeout(1800);     // Keycloak's 30-minute default
        existing.setSsoSessionMaxLifespan(36000);    // and its 10 hours
        when(api.findRealm("app")).thenReturn(Optional.of(existing));

        List<ChangeEntry> changes = reconciler.reconcile(new RealmDeclaration(
                "app",
                new RealmSettings(null, null, null, null, null, 604800, 2592000),
                null, null, null, null));

        ArgumentCaptor<RealmRepresentation> patch = ArgumentCaptor.forClass(RealmRepresentation.class);
        verify(api).updateRealm(eq("app"), patch.capture());
        assertThat(patch.getValue().getSsoSessionIdleTimeout()).isEqualTo(604800);
        assertThat(patch.getValue().getSsoSessionMaxLifespan()).isEqualTo(2592000);
        assertThat(changes.get(0).details()).contains("ssoSessionIdleTimeout", "ssoSessionMaxLifespan");
    }

    @Test
    @DisplayName("Session lifespans already as declared → SKIPPED")
    void skipsMatchingSessionLifespans() {
        RealmRepresentation existing = new RealmRepresentation();
        existing.setSsoSessionIdleTimeout(604800);
        existing.setSsoSessionMaxLifespan(2592000);
        when(api.findRealm("app")).thenReturn(Optional.of(existing));

        List<ChangeEntry> changes = reconciler.reconcile(new RealmDeclaration(
                "app",
                new RealmSettings(null, null, null, null, null, 604800, 2592000),
                null, null, null, null));

        verify(api, never()).updateRealm(any(), any());
        assertThat(changes.get(0).action()).isEqualTo("SKIPPED");
    }

    @Test
    @DisplayName("A realm Keycloak returns without lifespans differs from declared ones")
    void nullExistingLifespanIsADifference() {
        when(api.findRealm("app")).thenReturn(Optional.of(new RealmRepresentation()));

        List<ChangeEntry> changes = reconciler.reconcile(new RealmDeclaration(
                "app",
                new RealmSettings(null, null, null, null, null, 604800, null),
                null, null, null, null));

        assertThat(changes.get(0).action()).isEqualTo("UPDATED");
        assertThat(changes.get(0).details()).contains("ssoSessionIdleTimeout").doesNotContain("ssoSessionMaxLifespan");
    }

    @Test
    @DisplayName("A new realm is created with the declared session lifespans")
    void createsRealmWithSessionLifespans() {
        when(api.findRealm("app")).thenReturn(Optional.empty());

        reconciler.reconcile(new RealmDeclaration(
                "app",
                new RealmSettings(null, null, null, null, null, 604800, 2592000),
                null, null, null, null));

        ArgumentCaptor<RealmRepresentation> created = ArgumentCaptor.forClass(RealmRepresentation.class);
        verify(api).createRealm(created.capture());
        assertThat(created.getValue().getSsoSessionIdleTimeout()).isEqualTo(604800);
        assertThat(created.getValue().getSsoSessionMaxLifespan()).isEqualTo(2592000);
    }
}
