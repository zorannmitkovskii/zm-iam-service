package zm.iam.provisioning.reconcile;

import zm.iam.keycloak.KeycloakAdminApi;
import zm.iam.provisioning.dto.ClientDeclaration;
import zm.iam.provisioning.dto.ClientType;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.keycloak.representations.idm.ClientRepresentation;
import org.mockito.ArgumentCaptor;

import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class ClientReconcilerTest {

    @Test
    @DisplayName("Missing client → CREATE")
    void createsMissingClient() {
        KeycloakAdminApi api = mock(KeycloakAdminApi.class);
        when(api.findClient("app", "eventFE")).thenReturn(Optional.empty());

        List<ChangeEntry> changes = new ClientReconciler(api).reconcile("app",
                new ClientDeclaration("eventFE", ClientType.PUBLIC, true,
                        List.of("https://ivyevents.mk/*"), List.of("+"),
                        null, null, null, null));

        verify(api).createClient(eq("app"), any(ClientRepresentation.class));
        assertThat(changes.get(0).action()).isEqualTo("CREATED");
    }

    @Test
    @DisplayName("Existing client, everything matches → SKIPPED")
    void skipsWhenNothingDiffers() {
        KeycloakAdminApi api = mock(KeycloakAdminApi.class);
        ClientRepresentation existing = new ClientRepresentation();
        existing.setId("uuid-1");
        existing.setClientId("eventFE");
        existing.setPublicClient(true);
        existing.setRedirectUris(List.of("https://ivyevents.mk/*"));
        when(api.findClient("app", "eventFE")).thenReturn(Optional.of(existing));

        List<ChangeEntry> changes = new ClientReconciler(api).reconcile("app",
                new ClientDeclaration("eventFE", ClientType.PUBLIC, null,
                        List.of("https://ivyevents.mk/*"),
                        null, null, null, null, null));

        verify(api, never()).updateClient(any(), any());
        assertThat(changes.get(0).action()).isEqualTo("SKIPPED");
    }

    @Test
    @DisplayName("Existing client, new redirect URI → UPDATE with redirectUris in diff")
    void updatesRedirectUris() {
        KeycloakAdminApi api = mock(KeycloakAdminApi.class);
        ClientRepresentation existing = new ClientRepresentation();
        existing.setId("uuid-1");
        existing.setClientId("eventFE");
        existing.setPublicClient(true);
        existing.setRedirectUris(List.of("https://old.mk/*"));
        when(api.findClient("app", "eventFE")).thenReturn(Optional.of(existing));

        List<ChangeEntry> changes = new ClientReconciler(api).reconcile("app",
                new ClientDeclaration("eventFE", ClientType.PUBLIC, null,
                        List.of("https://new.mk/*"),
                        null, null, null, null, null));

        verify(api).updateClient(eq("app"), any());
        assertThat(changes.get(0).action()).isEqualTo("UPDATED");
        assertThat(changes.get(0).details()).contains("redirectUris");
    }

    @Test
    @DisplayName("directAccessGrantsEnabled=true is applied — public-auth login needs the password grant")
    void enablesDirectAccessGrantsWhenDeclared() {
        KeycloakAdminApi api = mock(KeycloakAdminApi.class);
        when(api.findClient("app", "eventFE")).thenReturn(Optional.empty());

        new ClientReconciler(api).reconcile("app",
                new ClientDeclaration("eventFE", ClientType.PUBLIC, true,
                        List.of("https://ivyevents.mk/*"), List.of("+"),
                        null, true, null, null));

        ArgumentCaptor<ClientRepresentation> sent = ArgumentCaptor.forClass(ClientRepresentation.class);
        verify(api).createClient(eq("app"), sent.capture());
        assertThat(sent.getValue().isDirectAccessGrantsEnabled()).isTrue();
    }

    @Test
    @DisplayName("Omitted directAccessGrantsEnabled stays off — ROPC is opt-in")
    void leavesDirectAccessGrantsOffByDefault() {
        KeycloakAdminApi api = mock(KeycloakAdminApi.class);
        when(api.findClient("app", "eventFE")).thenReturn(Optional.empty());

        new ClientReconciler(api).reconcile("app",
                new ClientDeclaration("eventFE", ClientType.PUBLIC, true,
                        List.of("https://ivyevents.mk/*"), List.of("+"),
                        null, null, null, null));

        ArgumentCaptor<ClientRepresentation> sent = ArgumentCaptor.forClass(ClientRepresentation.class);
        verify(api).createClient(eq("app"), sent.capture());
        assertThat(sent.getValue().isDirectAccessGrantsEnabled()).isFalse();
    }

    @Test
    @DisplayName("Existing client missing the grant → UPDATE naming it in the diff")
    void updatesWhenDirectAccessGrantsDiffers() {
        KeycloakAdminApi api = mock(KeycloakAdminApi.class);
        ClientRepresentation existing = new ClientRepresentation();
        existing.setId("uuid-1");
        existing.setClientId("eventFE");
        existing.setPublicClient(true);
        existing.setRedirectUris(List.of("https://ivyevents.mk/*"));
        existing.setDirectAccessGrantsEnabled(false);
        when(api.findClient("app", "eventFE")).thenReturn(Optional.of(existing));

        List<ChangeEntry> changes = new ClientReconciler(api).reconcile("app",
                new ClientDeclaration("eventFE", ClientType.PUBLIC, null,
                        List.of("https://ivyevents.mk/*"),
                        null, null, true, null, null));

        verify(api).updateClient(eq("app"), any());
        assertThat(changes.get(0).action()).isEqualTo("UPDATED");
        assertThat(changes.get(0).details()).contains("directAccessGrantsEnabled");
    }
}
