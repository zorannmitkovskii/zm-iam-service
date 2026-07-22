package zm.iam.publicauth;

import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.util.Optional;

/**
 * Maps an incoming request to the Keycloak realm it targets. Two paths:
 * <ol>
 *   <li>Explicit {@code appId} in the request body → direct realm lookup
 *       (a name we control, not an internal Keycloak string).</li>
 *   <li>{@code Origin} header → mapped through
 *       {@link PublicAuthProperties#getOriginToRealm()} to a realm name.
 *       Ivy FE today does NOT send appId, so Origin mapping must work
 *       from day one for backward compatibility.</li>
 * </ol>
 *
 * <p>Unknown Origin + no appId → {@link #resolve} returns
 * {@link Optional#empty()}; controllers turn that into a 400 rather than
 * silently defaulting to a wrong realm.
 */
@Slf4j
@Component
public class RealmResolver {

    private final PublicAuthProperties props;

    public RealmResolver(PublicAuthProperties props) {
        this.props = props;
    }

    public Optional<String> resolve(String originHeader, String explicitAppId) {
        if (explicitAppId != null && !explicitAppId.isBlank()) {
            String mapped = props.getAppIdToRealm().get(explicitAppId);
            if (mapped != null) return Optional.of(mapped);
            log.warn("[RealmResolver] Unknown appId '{}' — no mapping", explicitAppId);
            return Optional.empty();
        }
        if (originHeader == null || originHeader.isBlank()) return Optional.empty();
        String host = extractHost(originHeader);
        String mapped = props.getOriginToRealm().get(host);
        if (mapped == null) {
            log.warn("[RealmResolver] Origin host '{}' has no realm mapping — request will 400", host);
            return Optional.empty();
        }
        return Optional.of(mapped);
    }

    private static String extractHost(String origin) {
        // Strip scheme + port. "https://ivyevents.mk" → "ivyevents.mk".
        String noScheme = origin.replaceFirst("^[a-zA-Z]+://", "");
        int slash = noScheme.indexOf('/');
        if (slash > 0) noScheme = noScheme.substring(0, slash);
        int colon = noScheme.indexOf(':');
        if (colon > 0) noScheme = noScheme.substring(0, colon);
        return noScheme.toLowerCase();
    }
}
