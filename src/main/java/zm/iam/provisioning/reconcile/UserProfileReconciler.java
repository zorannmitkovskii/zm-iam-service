package zm.iam.provisioning.reconcile;

import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import zm.iam.keycloak.KeycloakAdminApi;

import java.util.ArrayList;
import java.util.List;

/**
 * Declares a manifest's {@code userProfileAttributes} on the realm.
 *
 * <p>This did not exist, and its absence was silent in the worst way. The field
 * was parsed into {@code RealmDeclaration}, counted towards "APPLIED with N
 * changes", and then dropped — nothing ever wrote it to Keycloak. Meanwhile
 * Keycloak's declarative user profile discards any attribute it has not been
 * told about, answering 204 as though it had stored it.
 *
 * <p>So every attribute a manifest declared was written by the product,
 * accepted, and gone: {@code eventIds} first, which emptied that claim for
 * every user, and then {@code orgId}, which is how an organization
 * administrator ended up with no organization in their token. Both looked like
 * bugs in whatever read the claim.
 *
 * <p>Additive on purpose. It adds what a manifest declares and never removes
 * anything: the profile also holds Keycloak's own username/email/firstName/
 * lastName, and one service's manifest is not entitled to delete an attribute
 * another service depends on. Dropping an attribute is a deliberate, separate
 * act — see the note on {@code eventIds} in ivy-events-be's manifest.
 */
@Slf4j
@Component
public class UserProfileReconciler {

    private final KeycloakAdminApi keycloak;

    public UserProfileReconciler(KeycloakAdminApi keycloak) {
        this.keycloak = keycloak;
    }

    public List<ChangeEntry> reconcile(String realmName, List<String> declared) {
        if (declared == null || declared.isEmpty()) {
            return List.of();
        }

        List<String> added = keycloak.ensureUserProfileAttributes(realmName, declared);

        List<ChangeEntry> changes = new ArrayList<>();
        for (String name : declared) {
            changes.add(added.contains(name)
                    ? ChangeEntry.created("userProfileAttribute", name)
                    : ChangeEntry.skipped("userProfileAttribute", name));
        }
        return changes;
    }
}
