package org.ivyinc.iam.provisioning.reconcile;

import lombok.extern.slf4j.Slf4j;
import org.ivyinc.iam.keycloak.KeycloakAdminApi;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;

/**
 * Create declared realm roles if missing. IAM-04 rule: never delete a
 * role — role removal is dangerous enough to require a separate,
 * deliberate flow (not a side-effect of a manifest edit).
 */
@Slf4j
@Component
public class RoleReconciler {

    private final KeycloakAdminApi keycloak;

    public RoleReconciler(KeycloakAdminApi keycloak) {
        this.keycloak = keycloak;
    }

    public List<ChangeEntry> reconcile(String realmName, List<String> declared) {
        if (declared == null || declared.isEmpty()) return List.of();
        List<ChangeEntry> changes = new ArrayList<>();
        for (String roleName : declared) {
            if (keycloak.realmRoleExists(realmName, roleName)) {
                changes.add(ChangeEntry.skipped("role", roleName));
            } else {
                keycloak.createRealmRole(realmName, roleName, null);
                changes.add(ChangeEntry.created("role", roleName));
            }
        }
        return changes;
    }
}
