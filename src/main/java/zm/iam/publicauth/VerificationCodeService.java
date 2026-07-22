package zm.iam.publicauth;

import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.argon2.Argon2PasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.security.SecureRandom;
import java.time.OffsetDateTime;
import java.util.Optional;

/**
 * Issues + verifies 6-digit numeric codes for public auth flows.
 * Argon2-hashed at rest so a DB leak doesn't hand out valid codes.
 *
 * <p>Verification is one-shot: on the first correct match the row's
 * {@code consumed_at} is set and no further verifications succeed.
 * Wrong attempts increment {@code attempts}; after
 * {@value #MAX_ATTEMPTS} the code is treated as invalid regardless of
 * the plaintext — the user must request a fresh one.
 */
@Slf4j
@Service
public class VerificationCodeService {

    /** 10-minute TTL matches the ivy-events-be behaviour today. */
    public static final int CODE_TTL_MINUTES = 10;

    /** How many wrong entries before a code is locked. */
    public static final int MAX_ATTEMPTS = 5;

    private static final SecureRandom RNG = new SecureRandom();

    private final VerificationCodeRepository repository;
    private final PasswordEncoder argon2 = Argon2PasswordEncoder.defaultsForSpringSecurity_v5_8();

    public VerificationCodeService(VerificationCodeRepository repository) {
        this.repository = repository;
    }

    /** Generate + persist a new code. Returns the PLAINTEXT (only the
     *  caller — the email sender — ever sees this; the DB has just the
     *  hash). */
    @Transactional
    public String issue(String realm, String email, VerificationPurpose purpose) {
        String plaintext = generate();
        OffsetDateTime now = OffsetDateTime.now();
        VerificationCode row = VerificationCode.builder()
                .codeHash(argon2.encode(plaintext))
                .purpose(purpose)
                .realm(realm)
                .email(email)
                .attempts(0)
                .expiresAt(now.plusMinutes(CODE_TTL_MINUTES))
                .createdAt(now)
                .build();
        repository.save(row);
        log.info("[VerificationCode] Issued {} code for email={} realm={} (expires in {}m)",
                purpose, email, realm, CODE_TTL_MINUTES);
        return plaintext;
    }

    /**
     * @return {@link VerifyOutcome} describing what happened. Callers
     *         match on the enum instead of parsing exception messages.
     */
    @Transactional
    public VerifyOutcome verify(String email, VerificationPurpose purpose, String plaintextCode) {
        Optional<VerificationCode> maybe = repository
                .findFirstByEmailAndPurposeAndConsumedAtIsNullOrderByCreatedAtDesc(email, purpose);
        if (maybe.isEmpty()) return VerifyOutcome.NOT_FOUND;

        VerificationCode row = maybe.get();
        if (OffsetDateTime.now().isAfter(row.getExpiresAt())) return VerifyOutcome.EXPIRED;
        if (row.getAttempts() >= MAX_ATTEMPTS) return VerifyOutcome.LOCKED_OUT;

        if (!argon2.matches(plaintextCode, row.getCodeHash())) {
            row.setAttempts(row.getAttempts() + 1);
            repository.save(row);
            log.info("[VerificationCode] Wrong code for email={} — attempt {}/{}",
                    email, row.getAttempts(), MAX_ATTEMPTS);
            return row.getAttempts() >= MAX_ATTEMPTS ? VerifyOutcome.LOCKED_OUT : VerifyOutcome.MISMATCH;
        }

        // Success — single-consume.
        row.setConsumedAt(OffsetDateTime.now());
        repository.save(row);
        log.info("[VerificationCode] Consumed {} code for email={}", purpose, email);
        return VerifyOutcome.OK;
    }

    /** 6 digits, cryptographically random, zero-padded. */
    private static String generate() {
        int n = RNG.nextInt(1_000_000);
        return String.format("%06d", n);
    }

    public enum VerifyOutcome {
        OK,
        MISMATCH,
        EXPIRED,
        LOCKED_OUT,
        NOT_FOUND
    }
}
