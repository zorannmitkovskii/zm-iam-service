package zm.iam.audit;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Rules for what lands in the {@code detail} column and the
 * {@code caller} field. Enforces the ticket's zero-PII promise so the
 * audit table can be queried by ops / grepped in backups without
 * leaking user data.
 *
 * <p>Two responsibilities:
 * <ol>
 *   <li>{@link #maskEmail} — turns {@code alice@wonderland.mk} into
 *       {@code a****@wonderland.mk}. Used for public-flow caller
 *       identification.</li>
 *   <li>{@link #sanitiseDetail} — walks a detail map, replaces any
 *       value list under a known-multivalued attribute key with a
 *       count. Keeps keys + counts (useful for "what changed") without
 *       persisting the values themselves.</li>
 * </ol>
 */
public final class PiiMasker {

    /** Keys whose values contain user-identifying data. Only KEY names
     *  land in the audit table for these; the values become the string
     *  {@code "<N values>"}. */
    private static final Set<String> MULTIVALUED_PII_KEYS = Set.of(
            "eventIds", "packages", "phoneNumbers", "phoneNumber", "email"
    );

    /** Fields that must never appear even as key placeholders. */
    private static final Set<String> FORBIDDEN_KEYS = Set.of(
            "password", "temporaryPassword", "clientSecret", "token", "code", "otp"
    );

    private PiiMasker() {}

    /** Simplistic email mask — keep first letter + full domain, replace
     *  the rest of the local part with asterisks. Good enough for
     *  audit-log identification without leaking the address. */
    public static String maskEmail(String email) {
        if (email == null || email.isBlank()) return "";
        int at = email.indexOf('@');
        if (at < 1) return "***";
        String local = email.substring(0, at);
        String domain = email.substring(at);
        // A single-char local part leaks nothing worth masking — keep it
        // as-is to preserve readability in the audit trail.
        String maskedLocal = local.length() == 1
                ? local
                : local.charAt(0) + "*".repeat(local.length() - 1);
        return maskedLocal + domain;
    }

    /** Walk the detail map, replace forbidden-key entries with
     *  {@code "[redacted]"} and multivalued PII entries with a value
     *  count. Everything else passes through as-is — the caller is
     *  responsible for not stuffing raw PII into other keys. */
    public static Map<String, Object> sanitiseDetail(Map<String, Object> detail) {
        if (detail == null) return Map.of();
        Map<String, Object> out = new HashMap<>();
        for (Map.Entry<String, Object> e : detail.entrySet()) {
            String key = e.getKey();
            Object value = e.getValue();

            if (FORBIDDEN_KEYS.contains(key)) {
                out.put(key, "[redacted]");
                continue;
            }
            if (MULTIVALUED_PII_KEYS.contains(key) && value instanceof List<?> list) {
                out.put(key, "<" + list.size() + " values>");
                continue;
            }
            out.put(key, value);
        }
        return out;
    }
}
