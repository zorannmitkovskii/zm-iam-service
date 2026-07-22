package zm.iam.publicauth;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.OffsetDateTime;
import java.util.UUID;

/**
 * One issued verification code. Plaintext code lives only in the email
 * we send; the DB has an argon2 hash.
 *
 * <p>Life cycle:
 * <ol>
 *   <li>{@code created_at} — request time. Rate-limiter reads (email,
 *       purpose, created_at) to enforce N-per-minute.</li>
 *   <li>{@code expires_at} = created_at + 10 min.</li>
 *   <li>{@code attempts} increments on every verify miss. Row is
 *       "locked out" after 5 failed attempts (code invalid until a
 *       fresh one is requested).</li>
 *   <li>{@code consumed_at} — set on the first successful verify.
 *       Row is dead after that; replays return "already used".</li>
 * </ol>
 */
@Data
@Builder
@Entity
@NoArgsConstructor
@AllArgsConstructor
@Table(name = "verification_codes")
public class VerificationCode {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @Column(name = "code_hash", nullable = false, length = 255)
    private String codeHash;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 32)
    private VerificationPurpose purpose;

    @Column(nullable = false, length = 64)
    private String realm;

    @Column(nullable = false, length = 255)
    private String email;

    @Column(nullable = false)
    private int attempts;

    @Column(name = "expires_at", nullable = false)
    private OffsetDateTime expiresAt;

    @Column(name = "consumed_at")
    private OffsetDateTime consumedAt;

    @Column(name = "created_at", nullable = false)
    private OffsetDateTime createdAt;
}
