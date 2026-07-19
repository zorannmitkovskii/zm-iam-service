package org.ivyinc.iam.provisioning.reconcile;

import lombok.extern.slf4j.Slf4j;
import org.ivyinc.iam.keycloak.KeycloakAdminApi;
import org.ivyinc.iam.provisioning.dto.ClientDeclaration;
import org.ivyinc.iam.provisioning.dto.ProtocolMapperDeclaration;
import org.keycloak.representations.idm.ProtocolMapperRepresentation;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

/**
 * Reconciles protocol mappers on ONE client. Delete rule (ticket AC 4):
 * <ul>
 *   <li>Mapper in current + in NEW → diff, UPDATE if fields differ.</li>
 *   <li>Mapper in current + NOT in NEW + WAS in PREVIOUS manifest of
 *       THIS service → DELETE. We planted it before; we own it.</li>
 *   <li>Mapper in current + NOT in NEW + NOT in PREVIOUS → SKIP.
 *       Somebody else planted it (admin console, another service); we
 *       don't touch it.</li>
 *   <li>Mapper NOT in current + in NEW → CREATE.</li>
 * </ul>
 *
 * <p>IAM-04 supports only {@code oidc-usermodel-attribute-mapper}
 * (mirrors ivy-events-be usage). Wider mapper types are follow-up.
 */
@Slf4j
@Component
public class ProtocolMapperReconciler {

    private static final String MAPPER_PROTOCOL = "openid-connect";
    private static final String MAPPER_TYPE = "oidc-usermodel-attribute-mapper";

    private final KeycloakAdminApi keycloak;

    public ProtocolMapperReconciler(KeycloakAdminApi keycloak) {
        this.keycloak = keycloak;
    }

    public List<ChangeEntry> reconcile(String realmName,
                                       String clientUuid,
                                       ClientDeclaration clientDecl,
                                       List<ProtocolMapperDeclaration> declared,
                                       List<ProtocolMapperDeclaration> previouslyDeclared) {
        List<ProtocolMapperDeclaration> newDecl = declared == null ? List.of() : declared;
        List<ProtocolMapperDeclaration> prevDecl = previouslyDeclared == null ? List.of() : previouslyDeclared;

        Map<String, ProtocolMapperRepresentation> currentByName = new HashMap<>();
        for (ProtocolMapperRepresentation m : keycloak.listProtocolMappers(realmName, clientUuid)) {
            currentByName.put(m.getName(), m);
        }
        Set<String> newNames = new HashSet<>();
        for (ProtocolMapperDeclaration d : newDecl) newNames.add(d.name());
        Set<String> prevNames = new HashSet<>();
        for (ProtocolMapperDeclaration d : prevDecl) prevNames.add(d.name());

        List<ChangeEntry> changes = new ArrayList<>();

        for (ProtocolMapperDeclaration d : newDecl) {
            ProtocolMapperRepresentation existing = currentByName.get(d.name());
            if (existing == null) {
                keycloak.createProtocolMapper(realmName, clientUuid, buildRep(d));
                changes.add(ChangeEntry.created("protocolMapper",
                        clientDecl.clientId() + "/" + d.name()));
                continue;
            }
            if (differs(existing, d)) {
                ProtocolMapperRepresentation update = buildRep(d);
                update.setId(existing.getId());
                keycloak.updateProtocolMapper(realmName, clientUuid, update);
                changes.add(ChangeEntry.updated("protocolMapper",
                        clientDecl.clientId() + "/" + d.name(), "config"));
            }
        }

        // DELETE — only mappers that were ours in the PREVIOUS manifest.
        for (Map.Entry<String, ProtocolMapperRepresentation> e : currentByName.entrySet()) {
            String name = e.getKey();
            if (newNames.contains(name)) continue;      // still declared → keep
            if (!prevNames.contains(name)) continue;    // never ours → keep
            keycloak.deleteProtocolMapper(realmName, clientUuid, e.getValue().getId(), name);
            changes.add(ChangeEntry.deleted("protocolMapper",
                    clientDecl.clientId() + "/" + name));
        }

        return changes;
    }

    private static ProtocolMapperRepresentation buildRep(ProtocolMapperDeclaration d) {
        ProtocolMapperRepresentation m = new ProtocolMapperRepresentation();
        m.setName(d.name());
        m.setProtocol(MAPPER_PROTOCOL);
        m.setProtocolMapper(MAPPER_TYPE);
        Map<String, String> config = new HashMap<>();
        config.put("user.attribute", d.userAttribute());
        config.put("claim.name", d.claim());
        config.put("jsonType.label", d.jsonType() == null ? "String" : d.jsonType());
        config.put("id.token.claim", "true");
        config.put("access.token.claim", "true");
        config.put("userinfo.token.claim", "true");
        config.put("multivalued", String.valueOf(Boolean.TRUE.equals(d.multivalued())));
        m.setConfig(config);
        return m;
    }

    private static boolean differs(ProtocolMapperRepresentation existing, ProtocolMapperDeclaration d) {
        Map<String, String> cfg = existing.getConfig() == null ? Map.of() : existing.getConfig();
        if (!Objects.equals(cfg.get("user.attribute"), d.userAttribute())) return true;
        if (!Objects.equals(cfg.get("claim.name"), d.claim())) return true;
        String desiredJson = d.jsonType() == null ? "String" : d.jsonType();
        if (!Objects.equals(cfg.get("jsonType.label"), desiredJson)) return true;
        String desiredMulti = String.valueOf(Boolean.TRUE.equals(d.multivalued()));
        return !Objects.equals(cfg.get("multivalued"), desiredMulti);
    }
}
