package zm.iam.provisioning.ownership;

/**
 * Kinds of Keycloak resources IAM tracks ownership for. Roles are
 * deliberately excluded — the ticket rule is "roles are shared,
 * create-if-missing, never deleted, no ownership tracked".
 */
public enum ResourceType {
    REALM,
    CLIENT,
    IDP
}
