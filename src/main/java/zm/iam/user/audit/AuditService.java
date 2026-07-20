package zm.iam.user.audit;

/**
 * Every user-management mutation logs one line through this interface.
 * IAM-11 lands the DB-backed implementation; until then
 * {@link LoggingAuditService} writes structured slf4j entries so ops
 * can grep and later replay into the eventual audit table.
 */
public interface AuditService {

    /**
     * @param action  {@code USER_CREATED} | {@code USER_DELETED} |
     *                {@code ROLES_UPDATED} | {@code ATTRIBUTES_PATCHED} |
     *                {@code USER_ENABLED} | {@code USER_DISABLED} |
     *                {@code PASSWORD_RESET}
     * @param realm   Keycloak realm the user lives in
     * @param userId  Keycloak user UUID; may be {@code null} on failed
     *                creation attempts
     * @param detail  optional context ("email=x@y.com" for create,
     *                changed keys for patch, ...)
     */
    void record(String action, String realm, String userId, String detail);
}
