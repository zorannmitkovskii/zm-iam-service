package zm.iam.publicauth;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.keycloak.representations.idm.UserRepresentation;
import zm.iam.audit.AuditService;
import zm.iam.common.exception.BusinessException;
import zm.iam.keycloak.KeycloakAdminApi;
import zm.iam.publicauth.dto.AccountType;
import zm.iam.publicauth.dto.RegisterRequest;
import zm.iam.publicauth.dto.VerifyEmailRequest;
import zm.iam.publicauth.notify.AuthNotificationGateway;

import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/** Signup creates personal accounts only; an agency is refused up front. */
class OrganizerSignupTest {

    private static final String REALM = "event-app";
    private static final String EMAIL = "agencija@example.com";
    private static final String USER_ID = "kc-user-1";

    private KeycloakAdminApi keycloak;
    private VerificationCodeService codes;
    private AuthNotificationGateway notifications;
    private PublicAuthService service;

    @BeforeEach
    void setUp() {
        keycloak = mock(KeycloakAdminApi.class);
        codes = mock(VerificationCodeService.class);
        notifications = mock(AuthNotificationGateway.class);
        service = new PublicAuthService(keycloak, codes, notifications,
                mock(KeycloakTokenClient.class), mock(AuditService.class));

        when(keycloak.findUserByEmail(REALM, EMAIL)).thenReturn(Optional.empty());
        when(keycloak.createUser(eq(REALM), eq(EMAIL), any(), any(), eq(false))).thenReturn(USER_ID);
        when(codes.issue(anyString(), anyString(), any())).thenReturn("123456");
    }

    @Test
    @DisplayName("An agency signup is refused before any user is created")
    void organizerIsRefused() {
        RegisterRequest request = new RegisterRequest(EMAIL, "Password1!", "Ана", "Ристеска",
                null, AccountType.ORGANIZER);

        assertThatThrownBy(() -> service.register(REALM, request))
                .isInstanceOf(BusinessException.class);

        verify(keycloak, never()).createUser(anyString(), anyString(), any(), any(), anyBoolean());
        verify(notifications, never()).emailVerification(anyString(), anyString(), anyString());
    }

    @Test
    @DisplayName("A personal signup creates the user and sends the verification code")
    void personalSignupCreatesTheUser() {
        service.register(REALM, new RegisterRequest(EMAIL, "Password1!", "Ана", "Ристеска",
                null, AccountType.PERSONAL));

        verify(keycloak).createUser(REALM, EMAIL, "Ана", "Ристеска", false);
        verify(notifications).emailVerification(REALM, EMAIL, "123456");
    }

    @Test
    @DisplayName("An older client that sends no account type gets a personal account")
    void missingAccountTypeIsPersonal() {
        service.register(REALM, new RegisterRequest(EMAIL, "Password1!", "Ана", "Ристеска", null, null));

        verify(keycloak).createUser(REALM, EMAIL, "Ана", "Ристеска", false);
    }

    @Test
    @DisplayName("Verifying enables the account and grants USER only")
    void verifyingGrantsUserOnly() {
        UserRepresentation user = new UserRepresentation();
        user.setId(USER_ID);
        user.setEmail(EMAIL);
        when(keycloak.findUserByEmail(REALM, EMAIL)).thenReturn(Optional.of(user));
        when(codes.verify(eq(EMAIL), any(), eq("123456")))
                .thenReturn(VerificationCodeService.VerifyOutcome.OK);

        service.verifyEmail(REALM, new VerifyEmailRequest(EMAIL, "123456", null));

        verify(keycloak).setUserEnabled(REALM, USER_ID, true);
        verify(keycloak).addUserRealmRoles(REALM, USER_ID, List.of("USER"));
    }
}
