package zm.iam.audit;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * IAM-11 tunables. Retention default is one calendar year — enough
 * runway for a post-incident forensics window without letting the table
 * grow unbounded.
 */
@Getter
@Setter
@ConfigurationProperties(prefix = "iam.audit")
public class AuditProperties {

    /** Delete audit rows older than this many days on each scheduled
     *  cleanup. Set to {@code 0} to disable retention (data grows
     *  forever). */
    private int retentionDays = 365;

    /** Cron expression for {@link AuditRetentionJob}. Default: 03:15
     *  every day (off-peak in EET). */
    private String retentionCron = "0 15 3 * * *";
}
