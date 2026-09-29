package zm.iam.provisioning.reconcile;

import zm.iam.keycloak.KeycloakAdminApi;
import zm.iam.provisioning.dto.IdentityProviderDeclaration;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.keycloak.representations.idm.IdentityProviderRepresentation;
import org.mockito.ArgumentCaptor;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
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

    @Test
    @DisplayName("A new Google provider trusts the email Google already verified")
    void newGoogleProviderTrustsEmail() {
        KeycloakAdminApi api = mock(KeycloakAdminApi.class);
        when(api.findIdp("app", "google")).thenReturn(Optional.empty());

        new IdpReconciler(api, CREDENTIALS).reconcile("app", List.of(GOOGLE));

        ArgumentCaptor<IdentityProviderRepresentation> created = ArgumentCaptor.forClass(IdentityProviderRepresentation.class);
        verify(api).createIdp(eq("app"), created.capture());
        assertThat(created.getValue().isTrustEmail()).isTrue();
    }

    @Test
    @DisplayName("An existing Google provider left untrusted is healed, even when its credentials match")
    void untrustedGoogleProviderIsHealed() {
        KeycloakAdminApi api = mock(KeycloakAdminApi.class);
        IdentityProviderRepresentation existing = existing("google", false);
        when(api.findIdp("app", "google")).thenReturn(Optional.of(existing));

        List<ChangeEntry> changes = new IdpReconciler(api, CREDENTIALS).reconcile("app", List.of(GOOGLE));

        ArgumentCaptor<IdentityProviderRepresentation> updated = ArgumentCaptor.forClass(IdentityProviderRepresentation.class);
        verify(api).updateIdp(eq("app"), eq("google"), updated.capture());
        assertThat(updated.getValue().isTrustEmail()).isTrue();
        assertThat(changes.get(0).action()).isEqualTo("UPDATED");
    }

    @Test
    @DisplayName("A trusted Google provider with the same credentials is left alone")
    void trustedGoogleProviderIsSkipped() {
        KeycloakAdminApi api = mock(KeycloakAdminApi.class);
        when(api.findIdp("app", "google")).thenReturn(Optional.of(existing("google", true)));

        List<ChangeEntry> changes = new IdpReconciler(api, CREDENTIALS).reconcile("app", List.of(GOOGLE));

        verify(api, never()).updateIdp(any(), any(), any());
        assertThat(changes.get(0).action()).isEqualTo("SKIPPED");
    }

    @Test
    @DisplayName("Trust is only granted to providers that verify email")
    void otherProvidersAreNotTrusted() {
        KeycloakAdminApi api = mock(KeycloakAdminApi.class);
        when(api.findIdp("app", "corp")).thenReturn(Optional.empty());

        new IdpReconciler(api, CREDENTIALS).reconcile("app", List.of(
                new IdentityProviderDeclaration("corp", "OIDC", "MY_ID", "MY_SECRET")));

        ArgumentCaptor<IdentityProviderRepresentation> created = ArgumentCaptor.forClass(IdentityProviderRepresentation.class);
        verify(api).createIdp(eq("app"), created.capture());
        assertThat(created.getValue().isTrustEmail()).isFalse();
    }

    private static final IdentityProviderDeclaration GOOGLE =
            new IdentityProviderDeclaration("google", "GOOGLE", "MY_ID", "MY_SECRET");

    private static final EnvVarResolver CREDENTIALS = new EnvVarResolver() {
        @Override public String get(String name) {
            return "MY_ID".equals(name) ? "id-value" : "secret-value";
        }
    };

    private static IdentityProviderRepresentation existing(String providerId, boolean trustEmail) {
        IdentityProviderRepresentation rep = new IdentityProviderRepresentation();
        rep.setAlias("google");
        rep.setProviderId(providerId);
        rep.setTrustEmail(trustEmail);
        rep.setConfig(new HashMap<>(Map.of("clientId", "id-value", "clientSecret", "secret-value")));
        return rep;
    }
}
