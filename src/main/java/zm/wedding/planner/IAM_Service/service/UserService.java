package zm.wedding.planner.IAM_Service.service;

import jakarta.ws.rs.core.Response;
import org.keycloak.OAuth2Constants;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.KeycloakBuilder;
import org.keycloak.admin.client.resource.UsersResource;
import org.keycloak.representations.idm.CredentialRepresentation;
import org.keycloak.representations.idm.UserRepresentation;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.util.Collections;
import java.util.List;
import java.util.Optional;
@Service
public class UserService {

    private final Keycloak keycloak;

    @Value("${keycloak.realm}")
    private String realm;

    public UserService(@Value("${keycloak.server-url}") String serverUrl,
                           @Value("${keycloak.admin-client-id}") String clientId,
                           @Value("${keycloak.admin-username}") String username,
                           @Value("${keycloak.admin-password}") String password) {
        this.keycloak = KeycloakBuilder.builder()
                .serverUrl(serverUrl)
                .realm(realm)
                .grantType(OAuth2Constants.PASSWORD)
                .clientId(clientId)
                .username(username)
                .password(password)
                .build();
    }

    /**
     * Create a new user in Keycloak
     */
    public String createUser(String username, String email, String password) {
        UserRepresentation user = new UserRepresentation();
        user.setUsername(username);
        user.setEmail(email);
        user.setEnabled(true);

        CredentialRepresentation credential = new CredentialRepresentation();
        credential.setType(CredentialRepresentation.PASSWORD);
        credential.setValue(password);
        credential.setTemporary(false);

        user.setCredentials(Collections.singletonList(credential));

        Response response = keycloak.realm(realm).users().create(user);
        if (response.getStatus() == 201) {
            return "User created successfully!";
        } else {
            return "Failed to create user: " + response.getStatus();
        }
    }

    /**
     * Get all users from Keycloak
     */
    public List<UserRepresentation> getAllUsers() {
        return keycloak.realm(realm).users().list();
    }

    /**
     * Get a user by ID
     */
    public Optional<UserRepresentation> getUserById(String userId) {
        return Optional.ofNullable(keycloak.realm(realm).users().get(userId).toRepresentation());
    }

    /**
     * Update user details in Keycloak
     */
    public String updateUser(String userId, String newEmail) {
        UsersResource usersResource = keycloak.realm(realm).users();
        UserRepresentation user = usersResource.get(userId).toRepresentation();
        user.setEmail(newEmail);
        usersResource.get(userId).update(user);
        return "User updated successfully!";
    }

    /**
     * Delete a user from Keycloak
     */
    public String deleteUser(String userId) {
        keycloak.realm(realm).users().get(userId).remove();
        return "User deleted successfully!";
    }
}
