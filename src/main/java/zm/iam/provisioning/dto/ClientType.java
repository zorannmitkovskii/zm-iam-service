package zm.iam.provisioning.dto;

/**
 * Keycloak client kind. Aligned with Keycloak's "Access Type" concept
 * pre-19 and the modern "Client authentication" toggle.
 * <ul>
 *   <li>{@link #PUBLIC} — public client, no client secret (browser-facing
 *       SPAs, mobile apps).</li>
 *   <li>{@link #CONFIDENTIAL} — confidential client with a secret
 *       (server-to-server flows).</li>
 * </ul>
 */
public enum ClientType {
    PUBLIC,
    CONFIDENTIAL
}
