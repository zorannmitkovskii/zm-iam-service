package zm.iam.publicauth.notify;

import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;
import zm.iam.publicauth.EmailSender;

/**
 * Fallback gateway — renders + sends inline via {@link EmailSender}. Used
 * until an environment has Kafka + zm-notification-service running. Active
 * unless {@code iam.notifications.via-events=true}.
 */
@Component
@ConditionalOnProperty(prefix = "iam.notifications", name = "via-events",
        havingValue = "false", matchIfMissing = true)
public class LocalEmailAuthNotificationGateway implements AuthNotificationGateway {

    private final EmailSender email;

    public LocalEmailAuthNotificationGateway(EmailSender email) {
        this.email = email;
    }

    @Override
    public void emailVerification(String realm, String toEmail, String code) {
        email.send(realm, toEmail, EmailSender.EmailTemplate.verificationCode(code, brandFor(realm)));
    }

    @Override
    public void passwordReset(String realm, String toEmail, String code) {
        email.send(realm, toEmail, EmailSender.EmailTemplate.passwordResetCode(code, brandFor(realm)));
    }

    private static String brandFor(String realm) {
        return "event-app".equals(realm) ? "Ivy Events" : realm;
    }
}
