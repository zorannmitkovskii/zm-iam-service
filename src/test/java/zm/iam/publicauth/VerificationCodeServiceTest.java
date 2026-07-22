package zm.iam.publicauth;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.OffsetDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The service under test is stateful (persistence-backed). Rather than
 * pulling in a JPA test slice, we stub the repository with an in-memory
 * List — the class under test only calls save + find methods, so a hand
 * stub is cleaner than Mockito ceremony.
 */
class VerificationCodeServiceTest {

    private InMemoryRepo repo;
    private VerificationCodeService service;

    @BeforeEach
    void setUp() {
        repo = new InMemoryRepo();
        service = new VerificationCodeService(repo);
    }

    @Test
    @DisplayName("Issue → verify with the returned plaintext → OK; second verify → NOT_FOUND (single-consume)")
    void issueThenVerifyOnce() {
        String code = service.issue("event-app", "a@b.mk", VerificationPurpose.EMAIL_VERIFY);

        assertThat(service.verify("a@b.mk", VerificationPurpose.EMAIL_VERIFY, code))
                .isEqualTo(VerificationCodeService.VerifyOutcome.OK);

        // Same code again — the row is consumed → the query filters it out.
        assertThat(service.verify("a@b.mk", VerificationPurpose.EMAIL_VERIFY, code))
                .isEqualTo(VerificationCodeService.VerifyOutcome.NOT_FOUND);
    }

    @Test
    @DisplayName("Wrong code → MISMATCH; attempts bump")
    void wrongCodeMismatch() {
        service.issue("event-app", "a@b.mk", VerificationPurpose.EMAIL_VERIFY);
        assertThat(service.verify("a@b.mk", VerificationPurpose.EMAIL_VERIFY, "000000"))
                .isEqualTo(VerificationCodeService.VerifyOutcome.MISMATCH);
        assertThat(repo.latest().getAttempts()).isEqualTo(1);
    }

    @Test
    @DisplayName("5 wrong attempts → LOCKED_OUT; correct code afterwards also LOCKED_OUT")
    void lockoutAfterFiveWrong() {
        String code = service.issue("event-app", "a@b.mk", VerificationPurpose.EMAIL_VERIFY);
        for (int i = 0; i < VerificationCodeService.MAX_ATTEMPTS; i++) {
            service.verify("a@b.mk", VerificationPurpose.EMAIL_VERIFY, "000000");
        }
        assertThat(service.verify("a@b.mk", VerificationPurpose.EMAIL_VERIFY, code))
                .isEqualTo(VerificationCodeService.VerifyOutcome.LOCKED_OUT);
    }

    @Test
    @DisplayName("Expired code → EXPIRED (rewound clock via direct row mutation)")
    void expiredCodeRejected() {
        String code = service.issue("event-app", "a@b.mk", VerificationPurpose.EMAIL_VERIFY);
        // Simulate 20 minutes passing (TTL is 10) by pushing expires_at into the past.
        repo.latest().setExpiresAt(OffsetDateTime.now().minusMinutes(1));
        assertThat(service.verify("a@b.mk", VerificationPurpose.EMAIL_VERIFY, code))
                .isEqualTo(VerificationCodeService.VerifyOutcome.EXPIRED);
    }

    @Test
    @DisplayName("Verify for a purpose we never issued → NOT_FOUND")
    void wrongPurposeIsolated() {
        service.issue("event-app", "a@b.mk", VerificationPurpose.EMAIL_VERIFY);
        assertThat(service.verify("a@b.mk", VerificationPurpose.PASSWORD_RESET, "123456"))
                .isEqualTo(VerificationCodeService.VerifyOutcome.NOT_FOUND);
    }

    // ── Hand-rolled stub for the small surface the service uses. ──

    static class InMemoryRepo implements VerificationCodeRepository {
        final List<VerificationCode> rows = new ArrayList<>();

        VerificationCode latest() { return rows.get(rows.size() - 1); }

        @Override
        public Optional<VerificationCode> findFirstByEmailAndPurposeAndConsumedAtIsNullOrderByCreatedAtDesc(
                String email, VerificationPurpose purpose) {
            AtomicReference<VerificationCode> best = new AtomicReference<>();
            for (VerificationCode r : rows) {
                if (!r.getEmail().equals(email)) continue;
                if (r.getPurpose() != purpose) continue;
                if (r.getConsumedAt() != null) continue;
                if (best.get() == null || r.getCreatedAt().isAfter(best.get().getCreatedAt())) {
                    best.set(r);
                }
            }
            return Optional.ofNullable(best.get());
        }

        @Override
        public long countByEmailAndPurposeAndCreatedAtAfter(
                String email, VerificationPurpose purpose, OffsetDateTime since) {
            return rows.stream()
                    .filter(r -> r.getEmail().equals(email) && r.getPurpose() == purpose
                            && r.getCreatedAt().isAfter(since))
                    .count();
        }

        @Override
        public List<VerificationCode> findAllByExpiresAtBefore(OffsetDateTime cutoff) {
            return rows.stream().filter(r -> r.getExpiresAt().isBefore(cutoff)).toList();
        }

        @Override
        public <S extends VerificationCode> S save(S entity) {
            if (entity.getId() == null) entity.setId(UUID.randomUUID());
            rows.removeIf(r -> r.getId().equals(entity.getId()));
            rows.add(entity);
            return entity;
        }

        // Unused surface — throw so we notice if we accidentally add a call.
        @Override public <S extends VerificationCode> List<S> saveAll(Iterable<S> entities) { throw new UnsupportedOperationException(); }
        @Override public Optional<VerificationCode> findById(UUID id) { throw new UnsupportedOperationException(); }
        @Override public boolean existsById(UUID id) { throw new UnsupportedOperationException(); }
        @Override public List<VerificationCode> findAll() { throw new UnsupportedOperationException(); }
        @Override public List<VerificationCode> findAllById(Iterable<UUID> ids) { throw new UnsupportedOperationException(); }
        @Override public long count() { throw new UnsupportedOperationException(); }
        @Override public void deleteById(UUID id) { throw new UnsupportedOperationException(); }
        @Override public void delete(VerificationCode entity) { throw new UnsupportedOperationException(); }
        @Override public void deleteAllById(Iterable<? extends UUID> ids) { throw new UnsupportedOperationException(); }
        @Override public void deleteAll(Iterable<? extends VerificationCode> entities) { throw new UnsupportedOperationException(); }
        @Override public void deleteAll() { throw new UnsupportedOperationException(); }
        @Override public void flush() {}
        @Override public <S extends VerificationCode> S saveAndFlush(S entity) { return save(entity); }
        @Override public <S extends VerificationCode> List<S> saveAllAndFlush(Iterable<S> entities) { throw new UnsupportedOperationException(); }
        @Override public void deleteAllInBatch(Iterable<VerificationCode> entities) { throw new UnsupportedOperationException(); }
        @Override public void deleteAllByIdInBatch(Iterable<UUID> ids) { throw new UnsupportedOperationException(); }
        @Override public void deleteAllInBatch() { throw new UnsupportedOperationException(); }
        @Override public VerificationCode getOne(UUID id) { throw new UnsupportedOperationException(); }
        @Override public VerificationCode getById(UUID id) { throw new UnsupportedOperationException(); }
        @Override public VerificationCode getReferenceById(UUID id) { throw new UnsupportedOperationException(); }
        @Override public <S extends VerificationCode> List<S> findAll(org.springframework.data.domain.Example<S> example) { throw new UnsupportedOperationException(); }
        @Override public <S extends VerificationCode> List<S> findAll(org.springframework.data.domain.Example<S> example, org.springframework.data.domain.Sort sort) { throw new UnsupportedOperationException(); }
        @Override public List<VerificationCode> findAll(org.springframework.data.domain.Sort sort) { throw new UnsupportedOperationException(); }
        @Override public org.springframework.data.domain.Page<VerificationCode> findAll(org.springframework.data.domain.Pageable pageable) { throw new UnsupportedOperationException(); }
        @Override public <S extends VerificationCode> Optional<S> findOne(org.springframework.data.domain.Example<S> example) { throw new UnsupportedOperationException(); }
        @Override public <S extends VerificationCode> org.springframework.data.domain.Page<S> findAll(org.springframework.data.domain.Example<S> example, org.springframework.data.domain.Pageable pageable) { throw new UnsupportedOperationException(); }
        @Override public <S extends VerificationCode> long count(org.springframework.data.domain.Example<S> example) { throw new UnsupportedOperationException(); }
        @Override public <S extends VerificationCode> boolean exists(org.springframework.data.domain.Example<S> example) { throw new UnsupportedOperationException(); }
        @Override public <S extends VerificationCode, R> R findBy(org.springframework.data.domain.Example<S> example, java.util.function.Function<org.springframework.data.repository.query.FluentQuery.FetchableFluentQuery<S>, R> queryFunction) { throw new UnsupportedOperationException(); }
    }
}
