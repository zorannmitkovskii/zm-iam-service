package zm.iam.publicauth.notify;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.stereotype.Component;

import java.util.HashMap;
import java.util.Map;

/**
 * Target-state gateway — emits a channel-agnostic notification event to
 * zm-notification-service over Kafka. Non-blocking: the auth flow fires the
 * event and returns; the notification service renders the template + sends.
 *
 * <p>Payload is a plain map matching zm-notification-service's
 * {@code NotificationRequested} record (that consumer ignores type headers),
 * so IAM stays decoupled from the service's classes.
 */
@Slf4j
@Component
@ConditionalOnProperty(prefix = "iam.notifications", name = "via-events", havingValue = "true")
public class EventAuthNotificationGateway implements AuthNotificationGateway {

    private final KafkaTemplate<String, Object> kafka;
    private final String topic;

    public EventAuthNotificationGateway(KafkaTemplate<String, Object> kafka,
                                        @Value("${notification.topic:zm.notifications.v1}") String topic) {
        this.kafka = kafka;
        this.topic = topic;
    }

    @Override
    public void emailVerification(String realm, String toEmail, String code) {
        publish("EMAIL_VERIFICATION", realm, toEmail, Map.of("code", code),
                "verify:" + realm + ":" + toEmail + ":" + code);
    }

    @Override
    public void passwordReset(String realm, String toEmail, String code) {
        publish("PASSWORD_RESET", realm, toEmail, Map.of("code", code),
                "reset:" + realm + ":" + toEmail + ":" + code);
    }

    private void publish(String template, String realm, String to,
                         Map<String, Object> params, String idempotencyKey) {
        Map<String, Object> event = new HashMap<>();
        event.put("channel", "EMAIL");
        event.put("template", template);
        event.put("to", to);
        event.put("realm", realm);
        event.put("params", params);
        event.put("idempotencyKey", idempotencyKey);
        kafka.send(topic, to, event);
        log.debug("[Notify] Emitted {} event for realm={} to={}", template, realm, to);
    }
}
