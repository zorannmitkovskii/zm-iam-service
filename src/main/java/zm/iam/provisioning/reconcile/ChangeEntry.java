package zm.iam.provisioning.reconcile;

/**
 * Audit line describing one thing a reconciler just did (or decided not
 * to do). Bubbles into the API response and gets stored in
 * {@code applied_manifests.changes} so operators can inspect what a
 * version bump actually touched in Keycloak.
 *
 * @param resource "realm" | "client" | "protocolMapper" | "role" | "idp"
 * @param name     natural identifier ("event-app", "eventFE/eventIds")
 * @param action   CREATED | UPDATED | SKIPPED | DELETED
 * @param details  optional extra context (fields updated, mapper name...)
 */
public record ChangeEntry(String resource, String name, String action, String details) {
    public static ChangeEntry created(String resource, String name) {
        return new ChangeEntry(resource, name, "CREATED", null);
    }
    public static ChangeEntry updated(String resource, String name, String details) {
        return new ChangeEntry(resource, name, "UPDATED", details);
    }
    public static ChangeEntry skipped(String resource, String name) {
        return new ChangeEntry(resource, name, "SKIPPED", null);
    }
    public static ChangeEntry deleted(String resource, String name) {
        return new ChangeEntry(resource, name, "DELETED", null);
    }
}
