package zm.iam.publicauth;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.time.OffsetDateTime;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Repository
public interface VerificationCodeRepository extends JpaRepository<VerificationCode, UUID> {

    /** Latest UNCONSUMED code for (email, purpose) — verify + attempts
     *  bump target. Ordering by created_at DESC gives us the most
     *  recently issued which is what the user's inbox has. */
    Optional<VerificationCode> findFirstByEmailAndPurposeAndConsumedAtIsNullOrderByCreatedAtDesc(
            String email, VerificationPurpose purpose);

    /** Rate-limit window scan — how many codes did we issue for this
     *  email + purpose since {@code since}. Powers "10 per minute" cap. */
    long countByEmailAndPurposeAndCreatedAtAfter(
            String email, VerificationPurpose purpose, OffsetDateTime since);

    /** Housekeeping. Retention isn't sensitive here — 24h is plenty
     *  since codes expire in 10 min. */
    List<VerificationCode> findAllByExpiresAtBefore(OffsetDateTime cutoff);
}
