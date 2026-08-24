package zm.iam.publicauth;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.keycloak.representations.idm.UserRepresentation;
import org.mockito.ArgumentCaptor;
import zm.iam.audit.AuditService;
import zm.iam.common.exception.BusinessException;
import zm.iam.keycloak.KeycloakAdminApi;
import zm.iam.publicauth.dto.AccountType;
import zm.iam.publicauth.dto.RegisterRequest;
import zm.iam.publicauth.dto.VerifyEmailRequest;
import zm.iam.publicauth.notify.AuthNotificationGateway;

import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Signing up as an agency rather than as a couple.
 *
 * <p>The behaviour being pinned is the one that used to be missing entirely:
 * every account was created personal, so an agency reached the CRM and met a
 * wall of 403s with nothing on screen explaining that an account type had been
 * chosen for them.
 */
class OrganizerSignupTest {

    private static final String REALM = "event-app";
    private static final String EMAIL = "agencija@example.com";
    private static final String USER_ID = "kc-user-1";

    private KeycloakAdminApi keycloak;
    private VerificationCodeService codes;
    private AuthNotificationGateway notifications;
    private OrganizationServiceClient organizations;
    private PublicAuthService service;

    @BeforeEach
    void setUp() {
        keycloak = mock(KeycloakAdminApi.class);
        codes = mock(VerificationCodeService.class);
        notifications = mock(AuthNotificationGateway.class);
        organizations = mock(OrganizationServiceClient.class);

        service = new PublicAuthService(keycloak, codes, notifications,
                mock(KeycloakTokenClient.class), mock(AuditService.class), organizations);

        when(keycloak.findUserByEmail(REALM, EMAIL)).thenReturn(Optional.empty());
        when(keycloak.createUser(eq(REALM), eq(EMAIL), any(), any(), eq(false))).thenReturn(USER_ID);
        when(codes.issue(anyString(), anyString(), any())).thenReturn("123456");
    }

    // ── registering ──────────────────────────────────────────────────────

    @Test
    @DisplayName("The chosen account type is remembered on the user, not asked for again")
    void choiceIsRemembered() {
        service.register(REALM, organizerRequest("Ивy Агенција"));

        // Stored at signup rather than resent at verification: a client that
        // forgets to resend it would silently downgrade an agency to personal.
        assertThat(attributesSetOn(USER_ID))
                .containsEntry("pendingAccountType", List.of("ORGANIZER"))
                .containsEntry("pendingOrganizationName", List.of("Ивy Агенција"));
    }

    @Test
    @DisplayName("A personal signup is recorded as personal and creates nothing else")
    void personalStaysPersonal() {
        service.register(REALM, new RegisterRequest(EMAIL, "Password1!", "Ана", "Ристеска",
                null, AccountType.PERSONAL, null));

        assertThat(attributesSetOn(USER_ID)).containsEntry("pendingAccountType", List.of("PERSONAL"));
        verify(organizations, never()).createOrganization(anyString());
    }

    @Test
    @DisplayName("An older client that sends no account type gets a personal account")
    void missingAccountTypeIsPersonal() {
        service.register(REALM, new RegisterRequest(EMAIL, "Password1!", "Ана", "Ристеска",
                null, null, null));

        // Fail-safe in the direction that costs least: a personal account that
        // should have been an agency is a support ticket; an agency created by
        // accident is a tenant in the registry nobody asked for.
        assertThat(attributesSetOn(USER_ID)).containsEntry("pendingAccountType", List.of("PERSONAL"));
    }

    @Test
    @DisplayName("An agency with no name is refused before the user is created")
    void organizerNeedsAName() {
        assertThatThrownBy(() -> service.register(REALM, organizerRequest("   ")))
                .isInstanceOf(BusinessException.class);

        verify(keycloak, never()).createUser(anyString(), anyString(), any(), any(), anyBoolean());
    }

    // ── verifying ────────────────────────────────────────────────────────

    @Test
    @DisplayName("Verifying an organizer creates the organization and makes them its admin")
    void verifyingAnOrganizerBuildsTheAgency() {
        UUID orgId = UUID.randomUUID();
        givenPendingUser("ORGANIZER", "Ивy Агенција");
        when(organizations.createOrganization("Ивy Агенција")).thenReturn(orgId);

        service.verifyEmail(REALM, new VerifyEmailRequest(EMAIL, "123456", null));

        verify(organizations).createOrganization("Ивy Агенција");
        assertThat(attributesSetOn(USER_ID)).containsEntry("orgId", List.of(orgId.toString()));

        // ORG_ADMIN, not ORGANIZER: the person signing up IS the agency, so
        // they get the role that can see its money and add its staff.
        verify(keycloak).addUserRealmRoles(REALM, USER_ID, List.of("ORG_ADMIN"));
        verify(keycloak).addUserRealmRoles(REALM, USER_ID, List.of("USER"));
    }

    @Test
    @DisplayName("The pending choice is cleared once it has been acted on")
    void pendingAttributesAreCleanedUp() {
        givenPendingUser("ORGANIZER", "Ивy Агенција");
        when(organizations.createOrganization(anyString())).thenReturn(UUID.randomUUID());

        service.verifyEmail(REALM, new VerifyEmailRequest(EMAIL, "123456", null));

        // Left behind, it is an instruction already carried out that the next
        // reader cannot tell apart from a pending one.
        verify(keycloak).removeUserAttribute(REALM, USER_ID, "pendingAccountType");
        verify(keycloak).removeUserAttribute(REALM, USER_ID, "pendingOrganizationName");
    }

    @Test
    @DisplayName("Verifying a personal account touches no registry and grants no ORG_ADMIN")
    void verifyingPersonalCreatesNoOrganization() {
        givenPendingUser("PERSONAL", "");

        service.verifyEmail(REALM, new VerifyEmailRequest(EMAIL, "123456", null));

        verify(organizations, never()).createOrganization(anyString());
        verify(keycloak, never()).addUserRealmRoles(REALM, USER_ID, List.of("ORG_ADMIN"));
        verify(keycloak).addUserRealmRoles(REALM, USER_ID, List.of("USER"));
    }

    @Test
    @DisplayName("If the registry refuses, no half-built agency is left behind")
    void aFailedRegistryLeavesNoOrgAdmin() {
        givenPendingUser("ORGANIZER", "Ивy Агенција");
        when(organizations.createOrganization(anyString()))
                .thenThrow(new OrganizationServiceClient
                        .OrganizationServiceUnavailableException("down", null));

        assertThatThrownBy(() -> service.verifyEmail(REALM, new VerifyEmailRequest(EMAIL, "123456", null)))
                .isInstanceOf(OrganizationServiceClient.OrganizationServiceUnavailableException.class);

        // ORG_ADMIN over an organization that does not exist is a permission
        // every check would refuse anyway, while the role says otherwise.
        verify(keycloak, never()).addUserRealmRoles(REALM, USER_ID, List.of("ORG_ADMIN"));
    }

    // ── plumbing ─────────────────────────────────────────────────────────

    private static boolean anyBoolean() {
        return org.mockito.ArgumentMatchers.anyBoolean();
    }

    private RegisterRequest organizerRequest(String organizationName) {
        return new RegisterRequest(EMAIL, "Password1!", "Ана", "Ристеска",
                null, AccountType.ORGANIZER, organizationName);
    }

    private void givenPendingUser(String accountType, String organizationName) {
        UserRepresentation user = new UserRepresentation();
        user.setId(USER_ID);
        user.setEmail(EMAIL);
        user.setFirstName("Ана");
        user.setLastName("Ристеска");
        user.setAttributes(Map.of(
                "pendingAccountType", List.of(accountType),
                "pendingOrganizationName", List.of(organizationName)));

        when(keycloak.findUserByEmail(REALM, EMAIL)).thenReturn(Optional.of(user));
        when(codes.verify(eq(EMAIL), any(), eq("123456")))
                .thenReturn(VerificationCodeService.VerifyOutcome.OK);
    }

    /** The attributes handed to the last {@code patchUserAttributes} call. */
    @SuppressWarnings("unchecked")
    private Map<String, List<String>> attributesSetOn(String userId) {
        ArgumentCaptor<Map<String, List<String>>> captor = ArgumentCaptor.forClass(Map.class);
        verify(keycloak, org.mockito.Mockito.atLeastOnce())
                .patchUserAttributes(eq(REALM), eq(userId), captor.capture(), any(), any());

        return captor.getAllValues().stream()
                .reduce(new java.util.HashMap<>(), (all, one) -> {
                    all.putAll(one);
                    return all;
                });
    }
}
