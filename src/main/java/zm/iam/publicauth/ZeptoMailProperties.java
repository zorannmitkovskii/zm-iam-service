package zm.iam.publicauth;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Config for the ZeptoMail-backed {@link EmailSender}. Bound from
 * {@code iam.email.zepto.*}. Defaults are baked into application.yml so IAM
 * sends transactional email out of the box; local dev disables it (see
 * application-local.yml) to fall back to {@link LoggingEmailSender}.
 */
@Getter
@Setter
@ConfigurationProperties(prefix = "iam.email.zepto")
public class ZeptoMailProperties {

    /** When false, {@link ZeptoMailEmailSender} is not created and the
     *  logging fallback is used instead. */
    private boolean enabled = true;

    /** ZeptoMail API key, sent verbatim as the {@code Authorization} header
     *  (already includes the {@code Zoho-enczapikey } prefix). */
    private String token;

    private String fromAddress;
    private String fromName;

    /** ZeptoMail API base (EU region by default). */
    private String baseUrl = "https://api.zeptomail.eu";
}
