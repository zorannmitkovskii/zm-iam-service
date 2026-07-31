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
 *       from day one for backward compatibility. A mapping key may be
 *       {@code host:port} ({@code localhost:5173}) or a bare {@code host}
 *       ({@code ivyevents.mk}); the more specific form wins.</li>
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
        String authority = extractAuthority(originHeader);
        String mapped = props.getOriginToRealm().get(authority);
        if (mapped != null) return Optional.of(mapped);

        String host = stripPort(authority);
        if (!host.equals(authority)) {
            mapped = props.getOriginToRealm().get(host);
            if (mapped != null) return Optional.of(mapped);
        }
        log.warn("[RealmResolver] Origin '{}' has no realm mapping (tried '{}' then '{}')"
                + " — request will 400", originHeader, authority, host);
        return Optional.empty();
    }

    /**
     * Scheme and path stripped, port KEPT: {@code "http://localhost:5173/x"}
     * → {@code "localhost:5173"}.
     *
     * <p>The port has to survive here. Locally every frontend is a different
     * port on {@code localhost}, so dropping it makes them indistinguishable
     * and one product's users resolve into another product's realm. Deployed
     * origins are distinct hostnames on the default port, which is why
     * {@link #resolve} falls back to the bare host — a mapping written as
     * {@code ivyevents.mk} still matches {@code https://ivyevents.mk}.
     */
    private static String extractAuthority(String origin) {
        String noScheme = origin.replaceFirst("^[a-zA-Z]+://", "");
        int slash = noScheme.indexOf('/');
        if (slash > 0) noScheme = noScheme.substring(0, slash);
        return noScheme.toLowerCase();
    }

    private static String stripPort(String authority) {
        int colon = authority.indexOf(':');
        return colon > 0 ? authority.substring(0, colon) : authority;
    }
}
