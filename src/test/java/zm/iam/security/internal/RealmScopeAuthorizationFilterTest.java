package zm.iam.security.internal;

import jakarta.servlet.FilterChain;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import zm.iam.provisioning.ownership.ResourceOwnership;
import zm.iam.provisioning.ownership.ResourceOwnershipRepository;
import zm.iam.provisioning.ownership.ResourceType;

import java.time.Instant;
import java.time.OffsetDateTime;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Unit tests for the realm-scope authorization filter. We exercise the
 * filter directly (no MockMvc, no Spring Security dispatch) so each
 * branch is asserted in isolation. The scenarios cover every Decision
 * enum in InternalAuditLogger except ALLOWED-only permutations.
 */
class RealmScopeAuthorizationFilterTest {

    private OwnedRealmsCache cache;
    private ResourceOwnershipRepository ownershipRepository;
    private InternalAuditLogger audit;
    private RealmScopeAuthorizationFilter filter;
    private FilterChain chain;

    @BeforeEach
    void setUp() {
        cache = mock(OwnedRealmsCache.class);
        ownershipRepository = mock(ResourceOwnershipRepository.class);
        audit = mock(InternalAuditLogger.class);
        filter = new RealmScopeAuthorizationFilter(cache, ownershipRepository, audit);
        chain = mock(FilterChain.class);
        SecurityContextHolder.clearContext();
    }

    @AfterEach
    void tearDown() {
        SecurityContextHolder.clearContext();
    }

    @Test
    @DisplayName("Valid azp + owned realm → chain invoked, ALLOWED audit")
    void ownedRealmIsAllowed() throws Exception {
        givenAuthenticatedAs("ivy-events-be-svc");
        when(cache.realmsFor("ivy-events-be")).thenReturn(Set.of("event-app"));

        MockHttpServletRequest req = internalRequest("event-app");
        MockHttpServletResponse resp = new MockHttpServletResponse();

        filter.doFilter(req, resp, chain);

        verify(chain, times(1)).doFilter(req, resp);
        verify(audit).audit(eq(InternalAuditLogger.Decision.ALLOWED),
                eq("ivy-events-be-svc"), eq("ivy-events-be"), eq("event-app"),
                any(), any(), any());
        assertThat(resp.getStatus()).isEqualTo(HttpServletResponse.SC_OK);
    }

    @Test
    @DisplayName("Cross-realm request → 403 with owner in body; chain NOT invoked")
    void crossRealmIsForbidden() throws Exception {
        givenAuthenticatedAs("ivy-events-be-svc");
        when(cache.realmsFor("ivy-events-be")).thenReturn(Set.of("event-app"));
        when(ownershipRepository.findAllByRealmOrderByResourceTypeAscResourceNameAsc("presmetko"))
                .thenReturn(List.of(ownershipRow("presmetko", "presmetko", "presmetko-be", ResourceType.REALM)));

        MockHttpServletRequest req = internalRequest("presmetko");
        MockHttpServletResponse resp = new MockHttpServletResponse();

        filter.doFilter(req, resp, chain);

        verify(chain, never()).doFilter(any(), any());
        assertThat(resp.getStatus()).isEqualTo(HttpServletResponse.SC_FORBIDDEN);
        assertThat(resp.getContentAsString()).contains("presmetko-be");
        verify(audit).audit(eq(InternalAuditLogger.Decision.DENIED_REALM_NOT_OWNED),
                eq("ivy-events-be-svc"), eq("ivy-events-be"), eq("presmetko"),
                any(), any(), eq("presmetko-be"));
    }

    @Test
    @DisplayName("Realm with no owner row → 403 with 'no service owns' message")
    void unownedRealmIsForbiddenGracefully() throws Exception {
        givenAuthenticatedAs("ivy-events-be-svc");
        when(cache.realmsFor("ivy-events-be")).thenReturn(Set.of("event-app"));
        when(ownershipRepository.findAllByRealmOrderByResourceTypeAscResourceNameAsc("no-such"))
                .thenReturn(List.of());

        MockHttpServletRequest req = internalRequest("no-such");
        MockHttpServletResponse resp = new MockHttpServletResponse();

        filter.doFilter(req, resp, chain);

        assertThat(resp.getStatus()).isEqualTo(HttpServletResponse.SC_FORBIDDEN);
        assertThat(resp.getContentAsString()).contains("no service currently owns realm 'no-such'");
    }

    @Test
    @DisplayName("Missing 'realm' query parameter → 400 with useful message")
    void missingRealmIs400() throws Exception {
        givenAuthenticatedAs("ivy-events-be-svc");

        MockHttpServletRequest req = new MockHttpServletRequest("GET", "/internal/users/search");
        MockHttpServletResponse resp = new MockHttpServletResponse();

        filter.doFilter(req, resp, chain);

        verify(chain, never()).doFilter(any(), any());
        assertThat(resp.getStatus()).isEqualTo(HttpServletResponse.SC_BAD_REQUEST);
        assertThat(resp.getContentAsString()).contains("realm");
        verify(audit).audit(eq(InternalAuditLogger.Decision.DENIED_MISSING_REALM_PARAM),
                any(), any(), any(), any(), any(), any());
    }

    @Test
    @DisplayName("Non-JwtAuthenticationToken principal → 401 (defensive fallback)")
    void wrongAuthTypeIs401() throws Exception {
        SecurityContextHolder.getContext().setAuthentication(
                new TestingAuthenticationToken("someone", "creds", "ROLE_iam-client"));

        MockHttpServletRequest req = internalRequest("event-app");
        MockHttpServletResponse resp = new MockHttpServletResponse();

        filter.doFilter(req, resp, chain);

        assertThat(resp.getStatus()).isEqualTo(HttpServletResponse.SC_UNAUTHORIZED);
    }

    @Test
    @DisplayName("azp missing '-svc' suffix → 403 with naming-convention message")
    void badAzpIs403() throws Exception {
        givenAuthenticatedAs("random-client");   // no -svc

        MockHttpServletRequest req = internalRequest("event-app");
        MockHttpServletResponse resp = new MockHttpServletResponse();

        filter.doFilter(req, resp, chain);

        assertThat(resp.getStatus()).isEqualTo(HttpServletResponse.SC_FORBIDDEN);
        assertThat(resp.getContentAsString()).contains("-svc");
        verify(audit).audit(eq(InternalAuditLogger.Decision.DENIED_BAD_AZP),
                eq("random-client"), any(), any(), any(), any(), any());
    }

    @Test
    @DisplayName("Requests outside /internal/** bypass the filter untouched")
    void nonInternalPathIsBypassed() throws Exception {
        // shouldNotFilter returns true → chain runs, no auth check
        MockHttpServletRequest req = new MockHttpServletRequest("GET", "/actuator/health");
        MockHttpServletResponse resp = new MockHttpServletResponse();

        filter.doFilter(req, resp, chain);

        verify(chain, times(1)).doFilter(req, resp);
    }

    // ── helpers ────────────────────────────────────────────────────

    private static MockHttpServletRequest internalRequest(String realmParam) {
        MockHttpServletRequest req = new MockHttpServletRequest("GET", "/internal/users/search");
        req.setParameter("realm", realmParam);
        return req;
    }

    private static void givenAuthenticatedAs(String azp) {
        Jwt jwt = Jwt.withTokenValue("t")
                .header("alg", "RS256")
                .subject("service-account-" + azp)
                .issuedAt(Instant.now())
                .expiresAt(Instant.now().plusSeconds(300))
                .claim("azp", azp)
                .claim("realm_access", Map.of("roles", List.of("iam-client")))
                .build();
        SecurityContextHolder.getContext().setAuthentication(new JwtAuthenticationToken(jwt));
    }

    private static ResourceOwnership ownershipRow(String realm, String resourceName,
                                                  String ownerService, ResourceType type) {
        return ResourceOwnership.builder()
                .id(UUID.randomUUID())
                .resourceType(type)
                .realm(realm)
                .resourceName(resourceName)
                .ownerService(ownerService)
                .createdAt(OffsetDateTime.now())
                .build();
    }

    // Convenience so the readability of the tests survives static-import
    // of Mockito.eq without importing the top of the file.
    private static <T> T eq(T value) { return org.mockito.ArgumentMatchers.eq(value); }
}
