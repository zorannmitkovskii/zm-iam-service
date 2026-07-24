package zm.iam.publicauth;

import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

/**
 * The only {@link EmailSender} left in IAM — it just LOGS the message. Real
 * email delivery moved to zm-notification-service: IAM emits events via
 * {@link zm.iam.publicauth.notify.EventAuthNotificationGateway} when
 * {@code iam.notifications.via-events=true}. This sender is the fallback used
 * by {@link zm.iam.publicauth.notify.LocalEmailAuthNotificationGateway} in
 * environments without Kafka — the code is readable from the log line so local
 * dev / tests still work.
 */
@Slf4j
@Component
public class LoggingEmailSender implements EmailSender {

    @Override
    public void send(String realm, String toEmail, EmailTemplate template) {
        log.info("[EmailSender/LOG] realm={} to={} subject='{}' body:\n{}",
                realm, toEmail, template.subject(), template.body());
    }
}
