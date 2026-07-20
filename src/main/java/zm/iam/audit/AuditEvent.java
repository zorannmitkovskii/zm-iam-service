package zm.iam.audit;

import lombok.Builder;

import java.util.Map;

/**
 * Immutable snapshot of one audit-worthy event. Callers build it via
 * Lombok's {@link Builder} then hand it to {@link AuditService#record}.
 *
 * @param caller     WHO did it — {@code azp} for internal calls,
 *                   {@code serviceId} for provisioning, {@code "PUBLIC:"} +
 *                   masked email for public flows.
 * @param realm      Keycloak realm the target lives in; nullable for
 *                   realm-agnostic operations (e.g. platform ownership
 *                   registration).
 * @param targetType kind of resource acted upon.
 * @param targetId   natural identifier (user UUID, client id, realm
 *                   name, manifest serviceId + version).
 * @param operation  short verb ({@code CREATE}, {@code UPDATE},
 *                   {@code DELETE}, {@code APPLY}, {@code DENY}).
 * @param detail     safe-to-log map — attribute KEYS, change counts,
 *                   reason codes. NEVER raw attribute values, passwords,
 *                   tokens.
 * @param success    {@code true} = operation completed; {@code false} =
 *                   attempt rejected or errored.
 */
@Builder
public record AuditEvent(
        String caller,
        String realm,
        TargetType targetType,
        String targetId,
        String operation,
        Map<String, Object> detail,
        boolean success
) {
    /** Handy for authorship checks — pretty prints without leaking
     *  {@code detail}. */
    public String short_() {
        return "AuditEvent{caller=" + caller + " " + operation + " " + targetType + "/" + targetId
                + " success=" + success + "}";
    }
}
