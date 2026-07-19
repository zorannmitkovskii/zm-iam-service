package org.ivyinc.iam.provisioning.reconcile;

import org.ivyinc.iam.keycloak.KeycloakAdminApi;
import org.ivyinc.iam.provisioning.dto.RealmDeclaration;
import org.ivyinc.iam.provisioning.dto.RealmSettings;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
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
                new RealmSettings(true, false, null, null, null),
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
                new RealmSettings(true, false, null, null, null),
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
                new RealmSettings(true, false, null, null, null),
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
                new RealmSettings(true, null, null, null, null),  // only loginWithEmailAllowed declared
                null, null, null, null));

        assertThat(changes.get(0).details()).doesNotContain("resetPasswordAllowed");
    }
}
