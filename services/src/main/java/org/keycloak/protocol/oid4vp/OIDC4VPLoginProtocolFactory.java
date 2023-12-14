package org.keycloak.protocol.oid4vp;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.jboss.logging.Logger;
import org.keycloak.Config;
import org.keycloak.events.EventBuilder;
import org.keycloak.models.ClientModel;
import org.keycloak.models.ClientScopeModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.ProtocolMapperModel;
import org.keycloak.models.RealmModel;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.keycloak.protocol.LoginProtocol;
import org.keycloak.protocol.LoginProtocolFactory;
import org.keycloak.protocol.oid4vp.mappers.OIDC4VPSubjectIdMapper;
import org.keycloak.protocol.oid4vp.mappers.OIDC4VPTargetRoleMapper;
import org.keycloak.protocol.oid4vp.mappers.OIDC4VPUserAttributeMapper;
import org.keycloak.representations.idm.ClientRepresentation;
import org.keycloak.services.managers.AppAuthManager;

import java.time.Clock;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

/**
 * This factory is required to get the capability of creating {@link OIDC4VPClientModel} using the SIOP-2 protocol.
 * Clients cannot be created without a matching protocol. We do not support logging into keycloak with it, nor any other
 * "native" functionality, thus we don't implement anything beside the
 */
public class OIDC4VPLoginProtocolFactory implements LoginProtocolFactory {

    private static final Logger LOGGER = Logger.getLogger(OIDC4VPLoginProtocolFactory.class);

    public static final String PROTOCOL_ID = "oidc4vp";

    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();
    private static final String CLIENT_ROLES_MAPPER = "client-roles";
    private static final String SUBJECT_ID_MAPPER = "subject-id";
    private static final String USERNAME_MAPPER = "username";
    private static final String EMAIL_MAPPER = "email";
    private static final String LAST_NAME_MAPPER = "last-name";
    private static final String FIRST_NAME_MAPPER = "first-name";

    private final Clock clock = Clock.systemUTC();

    private Map<String, ProtocolMapperModel> builtins = new HashMap<>();

    @Override
    public void init(Config.Scope config) {
        LOGGER.info("Initiate the protocol factory");
        builtins.put(CLIENT_ROLES_MAPPER,
                OIDC4VPTargetRoleMapper.create("id", "client roles"));
        builtins.put(SUBJECT_ID_MAPPER,
                OIDC4VPSubjectIdMapper.create("subject id", "id"));
        builtins.put(USERNAME_MAPPER,
                OIDC4VPUserAttributeMapper.create(USERNAME_MAPPER, "username", "username", false));
        builtins.put(EMAIL_MAPPER,
                OIDC4VPUserAttributeMapper.create(EMAIL_MAPPER, "email", "email", false));
        builtins.put(FIRST_NAME_MAPPER,
                OIDC4VPUserAttributeMapper.create(FIRST_NAME_MAPPER, "firstName", "firstName", false));
        builtins.put(LAST_NAME_MAPPER,
                OIDC4VPUserAttributeMapper.create(LAST_NAME_MAPPER, "lastName", "familyName", false));
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {
        // no-op
    }

    @Override
    public void close() {
        // no-op
    }

    @Override
    public Map<String, ProtocolMapperModel> getBuiltinMappers() {
        return builtins;
    }

    @Override
    public Object createProtocolEndpoint(KeycloakSession keycloakSession, EventBuilder event) {

        LOGGER.info("Create vc-issuer protocol endpoint");

        String issuerDid = Optional.ofNullable(keycloakSession.getContext().getRealm().getAttribute("issuerDid"))
                .orElseThrow(() -> new VCIssuerException("No issuerDid  configured."));
        String keyPath = Optional.ofNullable(keycloakSession.getContext().getRealm().getAttribute("keyPath"))
                .orElseThrow(() -> new VCIssuerException("No keyPath configured."));
        Optional<String> lpdType = Optional.ofNullable(keycloakSession.getContext().getRealm().getAttribute("ldpType"));
        Optional<String> jwtType = Optional.ofNullable(keycloakSession.getContext().getRealm().getAttribute("jwtType"));
        Optional<String> sdJwtType = Optional.ofNullable(keycloakSession.getContext().getRealm().getAttribute("sdJwtType"));

        Integer decoys = Optional.ofNullable(keycloakSession.getContext().getRealm().getAttribute("decoys")).map(Integer::valueOf).orElse(0);
        Optional<String> keyId = Optional.ofNullable(keycloakSession.getContext().getRealm().getAttribute("keyId"));
        return new OIDC4VPIssuerEndpoint(
                keycloakSession,
                issuerDid, keyPath,
                jwtType, sdJwtType, lpdType,
                new AppAuthManager.BearerTokenAuthenticator(
                        keycloakSession),
                OBJECT_MAPPER, clock,
                decoys, keyId
        );
    }

    @Override
    public void createDefaultClientScopes(RealmModel newRealm, boolean addScopesToExistingClients) {
        LOGGER.debugf("Create default scopes for realm %s", newRealm.getName());

        ClientScopeModel naturalPersonScope = KeycloakModelUtils.getClientScopeByName(newRealm, "natural_person");
        if (naturalPersonScope == null) {
            LOGGER.debug("Add natural person scope");
            naturalPersonScope = newRealm.addClientScope("natural_person");
            naturalPersonScope.setDescription(
                    "OIDC$VP Scope, that adds all properties required for a natural person.");
            naturalPersonScope.setProtocol(PROTOCOL_ID);
            naturalPersonScope.addProtocolMapper(builtins.get(SUBJECT_ID_MAPPER));
            naturalPersonScope.addProtocolMapper(builtins.get(CLIENT_ROLES_MAPPER));
            naturalPersonScope.addProtocolMapper(builtins.get(EMAIL_MAPPER));
            naturalPersonScope.addProtocolMapper(builtins.get(FIRST_NAME_MAPPER));
            naturalPersonScope.addProtocolMapper(builtins.get(LAST_NAME_MAPPER));
            newRealm.addDefaultClientScope(naturalPersonScope, true);
        }
    }

    @Override
    public void setupClientDefaults(ClientRepresentation rep, ClientModel newClient) {
        // validate before setting the defaults
        OIDC4VPClientRegistrationProvider.validate(rep);
    }

    @Override
    public LoginProtocol create(KeycloakSession session) {
        return new OIDC4VPLoginProtocol(session);
    }

    @Override
    public String getId() {
        return PROTOCOL_ID;
    }

}
