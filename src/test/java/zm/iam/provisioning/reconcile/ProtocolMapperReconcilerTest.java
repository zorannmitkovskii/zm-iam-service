package zm.iam.provisioning.reconcile;

import zm.iam.keycloak.KeycloakAdminApi;
import zm.iam.provisioning.dto.ClientDeclaration;
import zm.iam.provisioning.dto.ClientType;
import zm.iam.provisioning.dto.ProtocolMapperDeclaration;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.keycloak.representations.idm.ProtocolMapperRepresentation;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Rigorous coverage for the delete-if-previously-declared rule. The
 * decision matrix per mapper name:
 * <ul>
 *   <li>in current + in NEW → CREATE / UPDATE / SKIP based on diff</li>
 *   <li>in current + NOT in NEW + WAS in PREVIOUS → DELETE</li>
 *   <li>in current + NOT in NEW + NOT in PREVIOUS → skip (foreign)</li>
 *   <li>NOT in current + in NEW → CREATE</li>
 * </ul>
 */
class ProtocolMapperReconcilerTest {

    private static final ClientDeclaration CLIENT_DECL = new ClientDeclaration(
            "eventFE", ClientType.PUBLIC, null, null, null, null, null, null);

    @Test
    @DisplayName("Missing mapper → CREATE")
    void createsMissingMapper() {
        KeycloakAdminApi api = mock(KeycloakAdminApi.class);
        when(api.listProtocolMappers("app", "client-uuid")).thenReturn(List.of());

        List<ChangeEntry> changes = new ProtocolMapperReconciler(api).reconcile("app", "client-uuid",
                CLIENT_DECL,
                List.of(new ProtocolMapperDeclaration("eventIds", "eventIds", "eventIds", true, null)),
                List.of());

        verify(api).createProtocolMapper(eq("app"), eq("client-uuid"), any());
        assertThat(changes.get(0).action()).isEqualTo("CREATED");
    }

    @Test
    @DisplayName("Mapper present + declared unchanged → no update call")
    void skipsUnchangedMapper() {
        KeycloakAdminApi api = mock(KeycloakAdminApi.class);
        when(api.listProtocolMappers("app", "client-uuid"))
                .thenReturn(List.of(existingMapper("eventIds", "eventIds", "eventIds", "true", "String")));

        List<ChangeEntry> changes = new ProtocolMapperReconciler(api).reconcile("app", "client-uuid",
                CLIENT_DECL,
                List.of(new ProtocolMapperDeclaration("eventIds", "eventIds", "eventIds", true, null)),
                List.of());

        verify(api, never()).updateProtocolMapper(any(), any(), any());
        verify(api, never()).deleteProtocolMapper(any(), any(), any(), any());
        assertThat(changes).isEmpty();
    }

    @Test
    @DisplayName("Mapper present but claim differs → UPDATE")
    void updatesChangedMapper() {
        KeycloakAdminApi api = mock(KeycloakAdminApi.class);
        when(api.listProtocolMappers("app", "client-uuid"))
                .thenReturn(List.of(existingMapper("eventIds", "eventIds", "old-claim", "true", "String")));

        List<ChangeEntry> changes = new ProtocolMapperReconciler(api).reconcile("app", "client-uuid",
                CLIENT_DECL,
                List.of(new ProtocolMapperDeclaration("eventIds", "eventIds", "new-claim", true, null)),
                List.of());

        verify(api).updateProtocolMapper(eq("app"), eq("client-uuid"), any());
        assertThat(changes.get(0).action()).isEqualTo("UPDATED");
    }

    @Test
    @DisplayName("DELETE only if the mapper existed in PREVIOUS manifest (else foreign, leave alone)")
    void deletesOnlyPreviouslyDeclared() {
        KeycloakAdminApi api = mock(KeycloakAdminApi.class);
        when(api.listProtocolMappers("app", "client-uuid")).thenReturn(List.of(
                existingMapper("ours", "a", "a", "false", "String"),
                existingMapper("foreign", "b", "b", "false", "String")
        ));

        List<ChangeEntry> changes = new ProtocolMapperReconciler(api).reconcile("app", "client-uuid",
                CLIENT_DECL,
                List.of(),   // NEW: no mappers declared at all
                List.of(new ProtocolMapperDeclaration("ours", "a", "a", false, null))
        );

        verify(api).deleteProtocolMapper(eq("app"), eq("client-uuid"), anyString(), eq("ours"));
        verify(api, never()).deleteProtocolMapper(any(), any(), any(), eq("foreign"));
        assertThat(changes).extracting(ChangeEntry::action).containsExactly("DELETED");
    }

    private static ProtocolMapperRepresentation existingMapper(String name, String userAttr,
                                                                String claim, String multi, String jsonType) {
        ProtocolMapperRepresentation m = new ProtocolMapperRepresentation();
        m.setId("mapper-uuid-" + name);
        m.setName(name);
        m.setProtocol("openid-connect");
        m.setProtocolMapper("oidc-usermodel-attribute-mapper");
        Map<String, String> cfg = new HashMap<>();
        cfg.put("user.attribute", userAttr);
        cfg.put("claim.name", claim);
        cfg.put("multivalued", multi);
        cfg.put("jsonType.label", jsonType);
        m.setConfig(cfg);
        return m;
    }
}
