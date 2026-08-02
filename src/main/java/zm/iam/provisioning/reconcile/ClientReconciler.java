package zm.iam.provisioning.reconcile;

import lombok.extern.slf4j.Slf4j;
import zm.iam.keycloak.KeycloakAdminApi;
import zm.iam.provisioning.dto.ClientDeclaration;
import zm.iam.provisioning.dto.ClientType;
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
        // Off unless the manifest asks for it. It used to be unconditionally
        // off, which silently contradicted IAM's own /public/users/login —
        // that endpoint runs a password grant, so every login against an
        // IAM-provisioned client failed with unauthorized_client.
        target.setDirectAccessGrantsEnabled(Boolean.TRUE.equals(decl.directAccessGrantsEnabled()));

        if (confidential && decl.secretEnvRef() != null && !decl.secretEnvRef().isBlank()) {
            target.setSecret(requireEnv(decl.secretEnvRef(), decl.clientId()));
        }
    }

    /**
     * Resolves an {@code *EnvRef} against IAM's own environment.
     *
     * <p>Missing is fatal rather than skipped. A client silently left with a
     * Keycloak-generated secret looks provisioned and fails only later, at the
     * first call, in another service — which is the trail this method exists to
     * stop anyone walking again.
     */
    private static String requireEnv(String variableName, String clientId) {
        String value = System.getenv(variableName);
        if (value == null || value.isBlank()) {
            throw new IllegalStateException(
                    "Client '" + clientId + "' declares secretEnvRef=" + variableName
                            + " but that variable is not set on zm-iam-service");
        }
        return value;
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
        // Compared even when the declaration omits it: the desired state for
        // null is false, and an already-provisioned client left on true has
        // to be brought back down.
        if (Boolean.TRUE.equals(decl.directAccessGrantsEnabled())
                != Boolean.TRUE.equals(existing.isDirectAccessGrantsEnabled()))
            diffs.add("directAccessGrantsEnabled");
        // Keycloak does not return the secret on read, so there is nothing to
        // compare against. Declaring one means "make it this", every time —
        // otherwise a client provisioned before the declaration existed would
        // keep its generated secret forever.
        if (decl.secretEnvRef() != null && !decl.secretEnvRef().isBlank())
            diffs.add("secret");
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
