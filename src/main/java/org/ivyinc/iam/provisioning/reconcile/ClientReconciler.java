package org.ivyinc.iam.provisioning.reconcile;

import lombok.extern.slf4j.Slf4j;
import org.ivyinc.iam.keycloak.KeycloakAdminApi;
import org.ivyinc.iam.provisioning.dto.ClientDeclaration;
import org.ivyinc.iam.provisioning.dto.ClientType;
import org.keycloak.representations.idm.ClientRepresentation;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;

/**
 * Creates or updates the OIDC client. Fields managed here: publicClient
 * (from ClientType), pkce, redirectUris, webOrigins,
 * serviceAccountsEnabled, standardFlowEnabled, directAccessGrantsEnabled.
 * Protocol mappers are handled by {@link ProtocolMapperReconciler} in a
 * separate step so mapper diffing has access to the client's UUID.
 */
@Slf4j
@Component
public class ClientReconciler {

    private final KeycloakAdminApi keycloak;

    public ClientReconciler(KeycloakAdminApi keycloak) {
        this.keycloak = keycloak;
    }

    public List<ChangeEntry> reconcile(String realmName, ClientDeclaration decl) {
        Optional<ClientRepresentation> current = keycloak.findClient(realmName, decl.clientId());
        if (current.isEmpty()) {
            ClientRepresentation c = new ClientRepresentation();
            applyDeclarationOnto(c, decl);
            keycloak.createClient(realmName, c);
            return List.of(ChangeEntry.created("client", decl.clientId()));
        }
        ClientRepresentation existing = current.get();
        List<String> diffs = diff(existing, decl);
        if (diffs.isEmpty()) {
            return List.of(ChangeEntry.skipped("client", decl.clientId()));
        }
        // Update through the existing representation so KC-managed fields
        // (secret, node registration timeout, ...) survive.
        applyDeclarationOnto(existing, decl);
        keycloak.updateClient(realmName, existing);
        return List.of(ChangeEntry.updated("client", decl.clientId(), String.join(",", diffs)));
    }

    private static void applyDeclarationOnto(ClientRepresentation target, ClientDeclaration decl) {
        target.setClientId(decl.clientId());
        boolean confidential = decl.type() == ClientType.CONFIDENTIAL;
        target.setPublicClient(!confidential);
        target.setEnabled(true);
        if (decl.pkce() != null) {
            var attrs = target.getAttributes() == null ? new HashMap<String, String>()
                                                       : new HashMap<>(target.getAttributes());
            attrs.put("pkce.code.challenge.method", decl.pkce() ? "S256" : "");
            target.setAttributes(attrs);
        }
        if (decl.redirectUris() != null)           target.setRedirectUris(new ArrayList<>(decl.redirectUris()));
        if (decl.webOrigins() != null)             target.setWebOrigins(new ArrayList<>(decl.webOrigins()));
        if (decl.serviceAccountsEnabled() != null) target.setServiceAccountsEnabled(decl.serviceAccountsEnabled());
        target.setStandardFlowEnabled(!confidential
                || (decl.redirectUris() != null && !decl.redirectUris().isEmpty()));
        target.setDirectAccessGrantsEnabled(false);
    }

    private static List<String> diff(ClientRepresentation existing, ClientDeclaration decl) {
        List<String> diffs = new ArrayList<>();
        boolean confidentialDecl = decl.type() == ClientType.CONFIDENTIAL;
        if (existing.isPublicClient() == null || existing.isPublicClient() == confidentialDecl)
            diffs.add("type");
        if (decl.redirectUris() != null
                && !new HashSet<>(nullSafe(existing.getRedirectUris())).equals(new HashSet<>(decl.redirectUris())))
            diffs.add("redirectUris");
        if (decl.webOrigins() != null
                && !new HashSet<>(nullSafe(existing.getWebOrigins())).equals(new HashSet<>(decl.webOrigins())))
            diffs.add("webOrigins");
        if (decl.serviceAccountsEnabled() != null
                && !decl.serviceAccountsEnabled().equals(existing.isServiceAccountsEnabled()))
            diffs.add("serviceAccountsEnabled");
        if (decl.pkce() != null) {
            String current = existing.getAttributes() == null ? ""
                    : existing.getAttributes().getOrDefault("pkce.code.challenge.method", "");
            String desired = decl.pkce() ? "S256" : "";
            if (!desired.equals(current)) diffs.add("pkce");
        }
        return diffs;
    }

    private static <T> List<T> nullSafe(List<T> in) {
        return in == null ? List.of() : in;
    }
}
