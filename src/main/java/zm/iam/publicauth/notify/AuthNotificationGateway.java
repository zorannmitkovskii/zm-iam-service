package zm.iam.publicauth.notify;

/**
 * How public-auth flows deliver their transactional emails. Two impls,
 * chosen by {@code iam.notifications.via-events}:
 * <ul>
 *   <li>{@link EventAuthNotificationGateway} — emits a Kafka event to
 *       zm-notification-service (async, non-blocking). The target state.</li>
 *   <li>{@link LocalEmailAuthNotificationGateway} — sends inline via the
 *       local {@code EmailSender}. Fallback until Kafka + the notification
 *       service are live in an environment.</li>
 * </ul>
 */
public interface AuthNotificationGateway {

    void emailVerification(String realm, String toEmail, String code);

    void passwordReset(String realm, String toEmail, String code);
}
