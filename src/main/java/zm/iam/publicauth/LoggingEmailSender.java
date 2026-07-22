package zm.iam.publicauth;

import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.stereotype.Component;

/**
 * Fallback email sender — writes to the log instead of dialing SMTP.
 * Local dev + tests read the code from log lines; real environments
 * override with a ZeptoMail-backed bean (dedicated follow-up ticket).
 *
 * <p>{@code @ConditionalOnMissingBean} means "use me unless the
 * operator supplied something better" — no manual profile plumbing.
 */
@Slf4j
@Component
@ConditionalOnMissingBean(name = "zeptoMailEmailSender")
public class LoggingEmailSender implements EmailSender {

    @Override
    public void send(String realm, String toEmail, EmailTemplate template) {
        log.info("[EmailSender/LOG] realm={} to={} subject='{}' body:\n{}",
                realm, toEmail, template.subject(), template.body());
    }
}
