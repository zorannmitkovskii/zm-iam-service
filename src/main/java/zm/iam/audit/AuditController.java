package zm.iam.audit;

import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.format.annotation.DateTimeFormat;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import zm.iam.common.ApiResponse;

import java.time.OffsetDateTime;
import java.util.List;
import java.util.Map;

/**
 * Read-only view of the audit trail. Behind IAM-09's JWT + realm-scope
 * filter chain (already applies to {@code /internal/**}) — a caller
 * only sees rows in realms they own.
 *
 * <p>Query surface intentionally small: realm + targetId + time window.
 * Bigger analytics belong in a warehouse, not this endpoint.
 */
@Slf4j
@RestController
@RequestMapping("/internal/audit")
public class AuditController {

    private static final int MAX_PAGE_SIZE = 200;

    private final AuditLogRepository repository;

    public AuditController(AuditLogRepository repository) {
        this.repository = repository;
    }

    @GetMapping
    public ResponseEntity<ApiResponse<Map<String, Object>>> search(
            @RequestParam(required = false) String realm,
            @RequestParam(required = false) String targetId,
            @RequestParam(required = false)
            @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME) OffsetDateTime from,
            @RequestParam(required = false)
            @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME) OffsetDateTime to,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "50") int size) {

        int effectiveSize = Math.min(Math.max(size, 1), MAX_PAGE_SIZE);
        int effectivePage = Math.max(page, 0);

        Page<AuditLogEntry> result = repository.search(
                realm, targetId, from, to,
                PageRequest.of(effectivePage, effectiveSize));

        List<AuditRow> rows = result.getContent().stream()
                .map(AuditRow::from)
                .toList();
        Map<String, Object> body = Map.of(
                "totalElements", result.getTotalElements(),
                "totalPages", result.getTotalPages(),
                "page", effectivePage,
                "size", effectiveSize,
                "results", rows
        );
        return ResponseEntity.ok(ApiResponse.ok(body));
    }

    /** Projection — drops the {@code id} field (internal-only) but keeps
     *  everything a debugger needs. */
    public record AuditRow(
            OffsetDateTime occurredAt,
            String caller,
            String realm,
            TargetType targetType,
            String targetId,
            String operation,
            com.fasterxml.jackson.databind.JsonNode detail,
            boolean success) {
        static AuditRow from(AuditLogEntry e) {
            return new AuditRow(
                    e.getOccurredAt(), e.getCaller(), e.getRealm(),
                    e.getTargetType(), e.getTargetId(), e.getOperation(),
                    e.getDetail(), e.isSuccess());
        }
    }
}
