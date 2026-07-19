package zm.iam.provisioning.reconcile;

import lombok.extern.slf4j.Slf4j;
import zm.iam.keycloak.KeycloakAdminApi;
import zm.iam.provisioning.dto.RealmDeclaration;
import zm.iam.provisioning.dto.RealmSettings;
import org.keycloak.representations.idm.RealmRepresentation;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

/**
 * Creates the realm if missing; if present, sends a PUT ONLY when at
 * least one declared setting differs. Undeclared (null) settings never
 * overwrite — the manifest is additive.
 */
@Slf4j
@Component
public class RealmReconciler {

    private final KeycloakAdminApi keycloak;

    public RealmReconciler(KeycloakAdminApi keycloak) {
        this.keycloak = keycloak;
    }

    public List<ChangeEntry> reconcile(RealmDeclaration decl) {
        Optional<RealmRepresentation> current = keycloak.findRealm(decl.name());
        if (current.isEmpty()) {
            RealmRepresentation r = new RealmRepresentation();
            r.setRealm(decl.name());
            r.setEnabled(true);
            applyDeclaredSettings(r, decl.settings());
            keycloak.createRealm(r);
            return List.of(ChangeEntry.created("realm", decl.name()));
        }
        RealmRepresentation existing = current.get();
        List<String> fieldsChanged = diffSettings(existing, decl.settings());
        if (fieldsChanged.isEmpty()) {
            return List.of(ChangeEntry.skipped("realm", decl.name()));
        }
        RealmRepresentation patch = new RealmRepresentation();
        patch.setRealm(decl.name());
        applyDeclaredSettings(patch, decl.settings());
        keycloak.updateRealm(decl.name(), patch);
        return List.of(ChangeEntry.updated("realm", decl.name(), String.join(",", fieldsChanged)));
    }

    private static void applyDeclaredSettings(RealmRepresentation target, RealmSettings s) {
        if (s == null) return;
        if (s.loginWithEmailAllowed() != null) target.setLoginWithEmailAllowed(s.loginWithEmailAllowed());
        if (s.registrationAllowed() != null)   target.setRegistrationAllowed(s.registrationAllowed());
        if (s.resetPasswordAllowed() != null)  target.setResetPasswordAllowed(s.resetPasswordAllowed());
        if (s.rememberMe() != null)            target.setRememberMe(s.rememberMe());
        if (s.verifyEmail() != null)           target.setVerifyEmail(s.verifyEmail());
    }

    private static List<String> diffSettings(RealmRepresentation existing, RealmSettings decl) {
        List<String> diffs = new ArrayList<>();
        if (decl == null) return diffs;
        if (decl.loginWithEmailAllowed() != null && !decl.loginWithEmailAllowed().equals(existing.isLoginWithEmailAllowed()))
            diffs.add("loginWithEmailAllowed");
        if (decl.registrationAllowed() != null && !decl.registrationAllowed().equals(existing.isRegistrationAllowed()))
            diffs.add("registrationAllowed");
        if (decl.resetPasswordAllowed() != null && !decl.resetPasswordAllowed().equals(existing.isResetPasswordAllowed()))
            diffs.add("resetPasswordAllowed");
        if (decl.rememberMe() != null && !decl.rememberMe().equals(existing.isRememberMe()))
            diffs.add("rememberMe");
        if (decl.verifyEmail() != null && !decl.verifyEmail().equals(existing.isVerifyEmail()))
            diffs.add("verifyEmail");
        return diffs;
    }
}
