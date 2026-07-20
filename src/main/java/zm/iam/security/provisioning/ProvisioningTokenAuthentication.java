package zm.iam.security.provisioning;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.util.List;

/**
 * Authentication principal placed on {@link org.springframework.security.core.context.SecurityContextHolder}
 * once the bootstrap token verified against the argon2 hash for
 * {@code serviceId}. The principal name IS the serviceId — the
 * controller doesn't need to unwrap credentials to authorise.
 *
 * <p>Marked {@code authenticated=true} immediately in the constructor:
 * we build this token only after the filter has already verified the
 * hash. No further AuthenticationManager wiring needed.
 */
public class ProvisioningTokenAuthentication extends AbstractAuthenticationToken {

    private final String serviceId;

    public ProvisioningTokenAuthentication(String serviceId) {
        super(List.of(new SimpleGrantedAuthority("ROLE_PROVISIONING")));
        this.serviceId = serviceId;
        setAuthenticated(true);
    }

    @Override public Object getCredentials() { return ""; }

    /** Principal name IS the serviceId (kebab-case, lower). */
    @Override public Object getPrincipal() { return serviceId; }

    public String getServiceId() { return serviceId; }
}
