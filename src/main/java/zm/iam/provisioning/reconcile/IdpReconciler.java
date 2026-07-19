package zm.iam.provisioning.reconcile;

import lombok.extern.slf4j.Slf4j;
import zm.iam.keycloak.KeycloakAdminApi;
import zm.iam.provisioning.dto.IdentityProviderDeclaration;
import org.keycloak.representations.idm.IdentityProviderRepresentation;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

/**
 * External identity provider reconciliation. Two safety rules:
 * <ol>
 *   <li>Manifest carries only {@code *EnvRef} names; IdpReconciler
 *       resolves them via {@link EnvVarResolver} at apply time.</li>
 *   <li>Every referenced env var is resolved BEFORE any Keycloak write.
 *       If any is missing → throw {@link EnvVarMissingException} and let
 *       ProvisioningService's transaction roll back cleanly — no
 *       half-configured IdP planted.</li>
 * </ol>
 */
@Slf4j
@Component
public class IdpReconciler {

    private final KeycloakAdminApi keycloak;
    private final EnvVarResolver env;

    public IdpReconciler(KeycloakAdminApi keycloak, EnvVarResolver env) {
        this.keycloak = keycloak;
        this.env = env;
    }

    public List<ChangeEntry> reconcile(String realmName, List<IdentityProviderDeclaration> declared) {
        if (declared == null || declared.isEmpty()) return List.of();

        // Resolve every env var UP FRONT — better fast-fail with zero side
        // effects than a half-configured IdP mid-apply.
        Map<String, String[]> resolved = new HashMap<>();
        for (IdentityProviderDeclaration d : declared) {
            String clientId = requireEnv(d.clientIdEnvRef(), d.alias());
            String secret   = requireEnv(d.clientSecretEnvRef(), d.alias());
            resolved.put(d.alias(), new String[]{clientId, secret});
        }

        List<ChangeEntry> changes = new ArrayList<>();
        for (IdentityProviderDeclaration d : declared) {
            String[] creds = resolved.get(d.alias());
            Optional<IdentityProviderRepresentation> existing = keycloak.findIdp(realmName, d.alias());
            if (existing.isEmpty()) {
                keycloak.createIdp(realmName, buildRep(d, creds[0], creds[1]));
                changes.add(ChangeEntry.created("idp", d.alias()));
                continue;
            }
            if (differs(existing.get(), d, creds[0], creds[1])) {
                IdentityProviderRepresentation update = existing.get();
                applyOnto(update, d, creds[0], creds[1]);
                keycloak.updateIdp(realmName, d.alias(), update);
                changes.add(ChangeEntry.updated("idp", d.alias(), "config"));
            } else {
                changes.add(ChangeEntry.skipped("idp", d.alias()));
            }
        }
        return changes;
    }

    private String requireEnv(String name, String alias) {
        String v = env.get(name);
        if (!StringUtils.hasText(v)) {
            throw new EnvVarMissingException(
                    "IdP '" + alias + "' references env var '" + name
                            + "' but it is not set — refusing to write to Keycloak");
        }
        return v;
    }

    private static IdentityProviderRepresentation buildRep(IdentityProviderDeclaration d,
                                                           String clientId, String clientSecret) {
        IdentityProviderRepresentation rep = new IdentityProviderRepresentation();
        applyOnto(rep, d, clientId, clientSecret);
        return rep;
    }

    private static void applyOnto(IdentityProviderRepresentation target,
                                  IdentityProviderDeclaration d,
                                  String clientId, String clientSecret) {
        target.setAlias(d.alias());
        target.setProviderId(d.type().toLowerCase());
        target.setEnabled(true);
        Map<String, String> cfg = target.getConfig() == null ? new HashMap<>()
                                                             : new HashMap<>(target.getConfig());
        cfg.put("clientId", clientId);
        cfg.put("clientSecret", clientSecret);
        target.setConfig(cfg);
    }

    private static boolean differs(IdentityProviderRepresentation existing,
                                   IdentityProviderDeclaration d,
                                   String clientId, String clientSecret) {
        if (!Objects.equals(existing.getProviderId(), d.type().toLowerCase())) return true;
        Map<String, String> cfg = existing.getConfig() == null ? Map.of() : existing.getConfig();
        if (!Objects.equals(cfg.get("clientId"), clientId)) return true;
        return !Objects.equals(cfg.get("clientSecret"), clientSecret);
    }

    /** Thrown BEFORE any Keycloak write when a declared env-ref is unset. */
    public static class EnvVarMissingException extends RuntimeException {
        public EnvVarMissingException(String message) { super(message); }
    }
}
