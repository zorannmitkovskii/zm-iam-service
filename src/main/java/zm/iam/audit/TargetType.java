package zm.iam.audit;

/**
 * Kinds of things IAM audits. Kept as a Java enum backed by the DB's
 * VARCHAR column so adding a value (e.g. {@code SESSION}) is a code
 * change with no migration.
 */
public enum TargetType {
    USER,
    CLIENT,
    REALM,
    ROLE,
    IDP,
    MANIFEST
}
