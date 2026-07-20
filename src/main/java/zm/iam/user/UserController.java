package zm.iam.user;

import jakarta.validation.Valid;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import zm.iam.common.ApiResponse;
import zm.iam.user.dto.AttributePatchDto;
import zm.iam.user.dto.EnabledDto;
import zm.iam.user.dto.RolesPutDto;
import zm.iam.user.dto.UserCreateDto;
import zm.iam.user.dto.UserResponseDto;

import java.util.Optional;

/**
 * Internal user-management endpoints. All ops carry the target realm as
 * a required query parameter — this keeps the URL flat and matches the
 * shape ivy-events-be will pass in IVY-BE-02.
 *
 * <p>Auth wires in IAM-09; until then {@code /internal/**} is permitAll
 * in the security config with a matching TODO.
 */
@Slf4j
@RestController
@RequestMapping("/internal/users")
public class UserController {

    private final UserService users;

    public UserController(UserService users) {
        this.users = users;
    }

    @PostMapping
    public ResponseEntity<ApiResponse<UserResponseDto>> create(
            @RequestParam String realm,
            @Valid @RequestBody UserCreateDto dto) {
        UserResponseDto created = users.create(realm, dto);
        return ResponseEntity.status(HttpStatus.CREATED).body(ApiResponse.ok(created));
    }

    @GetMapping("/search")
    public ResponseEntity<ApiResponse<UserResponseDto>> searchByEmail(
            @RequestParam String realm,
            @RequestParam String email) {
        Optional<UserResponseDto> hit = users.searchByEmail(realm, email);
        return hit.map(u -> ResponseEntity.ok(ApiResponse.ok(u)))
                .orElseGet(() -> ResponseEntity.status(HttpStatus.NOT_FOUND)
                        .body(ApiResponse.fail("No user with email '" + email + "' in realm '" + realm + "'")));
    }

    @GetMapping("/{id}")
    public ResponseEntity<ApiResponse<UserResponseDto>> get(
            @RequestParam String realm,
            @PathVariable String id) {
        return ResponseEntity.ok(ApiResponse.ok(users.get(realm, id)));
    }

    @DeleteMapping("/{id}")
    public ResponseEntity<Void> delete(
            @RequestParam String realm,
            @PathVariable String id) {
        users.delete(realm, id);
        return ResponseEntity.noContent().build();
    }

    @PutMapping("/{id}/roles")
    public ResponseEntity<ApiResponse<UserResponseDto>> putRoles(
            @RequestParam String realm,
            @PathVariable String id,
            @Valid @RequestBody RolesPutDto dto) {
        return ResponseEntity.ok(ApiResponse.ok(users.putRoles(realm, id, dto)));
    }

    @PatchMapping("/{id}/attributes")
    public ResponseEntity<ApiResponse<UserResponseDto>> patchAttributes(
            @RequestParam String realm,
            @PathVariable String id,
            @Valid @RequestBody AttributePatchDto dto) {
        return ResponseEntity.ok(ApiResponse.ok(users.patchAttributes(realm, id, dto)));
    }

    @PutMapping("/{id}/enabled")
    public ResponseEntity<ApiResponse<UserResponseDto>> setEnabled(
            @RequestParam String realm,
            @PathVariable String id,
            @Valid @RequestBody EnabledDto dto) {
        return ResponseEntity.ok(ApiResponse.ok(users.setEnabled(realm, id, dto.enabled())));
    }
}
