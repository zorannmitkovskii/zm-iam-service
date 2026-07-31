package zm.iam.provisioning.reconcile;

import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import zm.iam.keycloak.KeycloakAdminApi;
import zm.iam.provisioning.dto.ClientDeclaration;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

/**
 * Grants the realm roles a client declares in {@code serviceAccountRoles}.
 *
 * <p>Until this existed the field was parsed into {@link ClientDeclaration} and
 * then silently dropped — every manifest that asked for {@code iam-client} or
 * {@code org-client} was applied successfully while the service account ended
 * up with none of them. The failure only appears later, as a 403 from the
 * service the caller was supposed to be allowed to reach.
 *
 * <p>Roles are granted to the service-account <em>user</em> Keycloak creates
 * behind the client, never to the client itself.
 *
 * <p>Roles are never revoked here. Removing a role is as dangerous as deleting
 * one — it can lock a running service out of a dependency mid-flight — so it
 * follows the same rule as {@link RoleReconciler}: additive only, removal is a
 * separate deliberate act.
 */
@Slf4j
@Component
public class ServiceAccountRoleReconciler {

    private final KeycloakAdminApi keycloak;

    public ServiceAccountRoleReconciler(KeycloakAdminApi keycloak) {
        this.keycloak = keycloak;
    }

    public List<ChangeEntry> reconcile(String realmName, ClientDeclaration decl) {
        List<String> declared = decl.serviceAccountRoles();
        if (declared == null || declared.isEmpty()) {
            return List.of();
        }

        Optional<String> serviceAccountUserId =
                keycloak.findServiceAccountUserId(realmName, decl.clientId());
        if (serviceAccountUserId.isEmpty()) {
            // Declaring roles on a client without service accounts enabled is a
            // manifest mistake, but not one worth aborting an otherwise valid
            // apply for — surface it as a change entry the operator will see.
            log.warn("[ServiceAccountRoleReconciler] Client '{}' in realm '{}' has no service "
                    + "account user; cannot grant {}", decl.clientId(), realmName, declared);
            return List.of(new ChangeEntry("serviceAccountRole", decl.clientId(),
                    "SKIPPED", "no service account user — is serviceAccountsEnabled set?"));
        }

        String userId = serviceAccountUserId.get();
        List<String> alreadyHeld = keycloak.userRealmRoleNames(realmName, userId);

        List<ChangeEntry> changes = new ArrayList<>();
        List<String> toGrant = new ArrayList<>();
        for (String roleName : declared) {
            String qualified = decl.clientId() + "/" + roleName;
            if (alreadyHeld.contains(roleName)) {
                changes.add(ChangeEntry.skipped("serviceAccountRole", qualified));
            } else if (!keycloak.realmRoleExists(realmName, roleName)) {
                // The role belongs to another service's manifest and that
                // manifest has not been applied yet. Ordering between services
                // is not something this service can control, so say so plainly
                // instead of failing the whole apply.
                log.warn("[ServiceAccountRoleReconciler] Realm role '{}' does not exist in '{}' yet; "
                        + "'{}' will not receive it until the owning manifest is applied",
                        roleName, realmName, decl.clientId());
                changes.add(new ChangeEntry("serviceAccountRole", qualified,
                        "SKIPPED", "realm role does not exist yet"));
            } else {
                toGrant.add(roleName);
                changes.add(ChangeEntry.created("serviceAccountRole", qualified));
            }
        }

        if (!toGrant.isEmpty()) {
            keycloak.addUserRealmRoles(realmName, userId, toGrant);
        }
        return changes;
    }
}
