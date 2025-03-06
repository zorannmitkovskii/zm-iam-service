package zm.wedding.planner.IAM_Service.controller;

import lombok.RequiredArgsConstructor;
import org.keycloak.representations.idm.RoleRepresentation;
import org.keycloak.representations.idm.UserRepresentation;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import zm.wedding.planner.IAM_Service.service.UserService;

import java.util.List;
import java.util.Optional;

@RestController
@RequestMapping("/api/users")
@RequiredArgsConstructor
public class UserController {
    private final UserService userService;

    @PostMapping
    public ResponseEntity<String> createUser(@RequestParam String username,
                                             @RequestParam String email,
                                             @RequestParam String password) {
        return ResponseEntity.ok(userService.createUser(username, email, password));
    }

    @GetMapping
    public ResponseEntity<List<UserRepresentation>> getAllUsers() {
        return ResponseEntity.ok(userService.getAllUsers());
    }

    @GetMapping("/{userId}")
    public ResponseEntity<Optional<UserRepresentation>> getUserById(@PathVariable String userId) {
        return ResponseEntity.ok(userService.getUserById(userId));
    }

    @PutMapping("/{userId}")
    public ResponseEntity<String> updateUser(@PathVariable String userId,
                                             @RequestParam String newEmail) {
        return ResponseEntity.ok(userService.updateUser(userId, newEmail));
    }

    @DeleteMapping("/{userId}")
    public ResponseEntity<String> deleteUser(@PathVariable String userId) {
        return ResponseEntity.ok(userService.deleteUser(userId));
    }

    @PostMapping
    public ResponseEntity<String> createRole(@RequestParam String roleName) {
        return ResponseEntity.ok(userService.createRole(roleName));
    }

    @GetMapping("/{roleName}")
    public ResponseEntity<Optional<RoleRepresentation>> getRole(@PathVariable String roleName) {
        return ResponseEntity.ok(userService.getRole(roleName));
    }

    @PostMapping("/assign")
    public ResponseEntity<String> assignRoleToUser(@RequestParam String userId,
                                                   @RequestParam String roleName) {
        return ResponseEntity.ok(userService.assignRoleToUser(userId, roleName));
    }

    @DeleteMapping("/remove")
    public ResponseEntity<String> removeRoleFromUser(@RequestParam String userId,
                                                     @RequestParam String roleName) {
        return ResponseEntity.ok(userService.removeRoleFromUser(userId, roleName));
    }

    @GetMapping("/user/{userId}")
    public ResponseEntity<List<RoleRepresentation>> getUserRoles(@PathVariable String userId) {
        return ResponseEntity.ok(userService.getUserRoles(userId));
    }
}
