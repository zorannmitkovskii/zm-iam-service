package zm.iam.security.internal;

import java.util.Optional;

/**
 * Convention mapper: the {@code azp} (authorized party) claim in a
 * client_credentials JWT is a Keycloak client id — e.g.
 * {@code ivy-events-be-svc}. Our provisioning contract requires every
 * service-account client to be suffixed with {@code -svc} so we can
 * cleanly distinguish "the client id" from "the logical service id"
 * (e.g. the manifest's {@code serviceId} field, which is the same
 * string minus the suffix).
 *
 * <p>Rejecting clients without the {@code -svc} suffix is intentional:
 * accepting them would blur the boundary between a service-account
 * client and any random client in {@code zm-services}, and IAM-06's
 * ownership model is keyed on the un-suffixed serviceId. Reject early
 * and force the caller to fix their provisioning manifest rather than
 * silently allowing an unowned realm through.
 */
public final class ServiceIdFromAzp {

    public static final String SVC_SUFFIX = "-svc";

    private ServiceIdFromAzp() {}

    /** Returns the derived serviceId or {@link Optional#empty()} if the
     *  azp claim is null/blank OR does not end with {@link #SVC_SUFFIX}. */
    public static Optional<String> map(String azp) {
        if (azp == null) return Optional.empty();
        String trimmed = azp.trim();
        if (trimmed.isEmpty()) return Optional.empty();
        if (!trimmed.endsWith(SVC_SUFFIX)) return Optional.empty();
        String serviceId = trimmed.substring(0, trimmed.length() - SVC_SUFFIX.length());
        return serviceId.isEmpty() ? Optional.empty() : Optional.of(serviceId);
    }
}
