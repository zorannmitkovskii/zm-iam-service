package zm.iam.provisioning.reconcile;

import zm.iam.keycloak.KeycloakAdminApi;
import zm.iam.provisioning.dto.IdentityProviderDeclaration;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.keycloak.representations.idm.IdentityProviderRepresentation;

import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class IdpReconcilerTest {

    @Test
    @DisplayName("Missing env var → EnvVarMissingException BEFORE any Keycloak write")
    void missingEnvVarBailsBeforeKeycloakWrite() {
        KeycloakAdminApi api = mock(KeycloakAdminApi.class);
        EnvVarResolver env = new EnvVarResolver() {
            @Override public String get(String name) { return null; }
        };
        IdpReconciler reconciler = new IdpReconciler(api, env);

        assertThatThrownBy(() -> reconciler.reconcile("app", List.of(
                new IdentityProviderDeclaration("google", "GOOGLE", "MY_ID", "MY_SECRET"))))
                .isInstanceOf(IdpReconciler.EnvVarMissingException.class)
                .hasMessageContaining("MY_ID");

        verify(api, never()).createIdp(any(), any());
        verify(api, never()).updateIdp(any(), any(), any());
    }

    @Test
    @DisplayName("Env vars set, IdP missing → CREATE")
    void createsMissingIdp() {
        KeycloakAdminApi api = mock(KeycloakAdminApi.class);
        when(api.findIdp("app", "google")).thenReturn(Optional.empty());
        EnvVarResolver env = new EnvVarResolver() {
            @Override public String get(String name) {
                return "MY_ID".equals(name) ? "id-value" : "secret-value";
            }
        };

        List<ChangeEntry> changes = new IdpReconciler(api, env).reconcile("app", List.of(
                new IdentityProviderDeclaration("google", "GOOGLE", "MY_ID", "MY_SECRET")));

        verify(api).createIdp(eq("app"), any(IdentityProviderRepresentation.class));
        assertThat(changes.get(0).action()).isEqualTo("CREATED");
    }
}
