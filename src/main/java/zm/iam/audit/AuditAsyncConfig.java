package zm.iam.audit;

import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.task.TaskExecutor;
import org.springframework.scheduling.annotation.EnableAsync;
import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.scheduling.concurrent.ThreadPoolTaskExecutor;

/**
 * Dedicated executor for audit writes so they don't share a pool with
 * anything else. Sized small on purpose — audit shouldn't queue up
 * thousands of writes; if we see the queue back up, that's a signal
 * something's wrong (usually the DB), not "we need more threads".
 *
 * <p>{@code CallerRunsPolicy} on rejection means the calling business
 * thread does the insert itself — the audit trail keeps up at the cost
 * of a brief latency spike, and the caller sees the DB error surfaced
 * inline (which the DbAuditService swallows).
 */
@Slf4j
@Configuration
@EnableAsync
@EnableScheduling
@EnableConfigurationProperties(AuditProperties.class)
public class AuditAsyncConfig {

    @Bean("auditTaskExecutor")
    public TaskExecutor auditTaskExecutor() {
        ThreadPoolTaskExecutor exec = new ThreadPoolTaskExecutor();
        exec.setCorePoolSize(2);
        exec.setMaxPoolSize(4);
        exec.setQueueCapacity(256);
        exec.setThreadNamePrefix("audit-");
        exec.setRejectedExecutionHandler(new java.util.concurrent.ThreadPoolExecutor.CallerRunsPolicy());
        exec.initialize();
        return exec;
    }
}
