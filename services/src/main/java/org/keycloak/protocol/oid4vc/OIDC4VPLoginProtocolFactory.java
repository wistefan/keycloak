package org.keycloak.protocol.oid4vc;

import com.fasterxml.jackson.core.JsonProcessingException;
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
import org.keycloak.protocol.oid4vc.issuance.OIDC4VPIssuerEndpoint;
import org.keycloak.protocol.oid4vc.issuance.VCIssuerException;
import org.keycloak.protocol.oid4vc.issuance.mappers.OIDC4VPSubjectIdMapper;
import org.keycloak.protocol.oid4vc.issuance.mappers.OIDC4VPTargetRoleMapper;
import org.keycloak.protocol.oid4vc.issuance.mappers.OIDC4VPUserAttributeMapper;
import org.keycloak.protocol.oid4vc.issuance.signing.*;
import org.keycloak.protocol.oid4vc.model.Format;
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
        try {
            LOGGER.infof("Initiate the protocol factory. Config is %s", OBJECT_MAPPER.writeValueAsString(config));
        } catch (JsonProcessingException e) {
            throw new RuntimeException(e);
        }
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

        Map<Format, VCSigningService> signingServices = new HashMap<>();

        // handle ldp-proofs
        boolean vcmdEnabled = Optional.ofNullable(keycloakSession.getContext().getRealm().getAttribute("vcdmEnabled")).map(Boolean::valueOf).orElse(false);
        Optional<String> ldpProofType = Optional.ofNullable(keycloakSession.getContext().getRealm().getAttribute("ldpProofType"));
        Optional<String> vcmdKeyPath = Optional.ofNullable(keycloakSession.getContext().getRealm().getAttribute("vcdmKeyPath"));
        Optional<String> vcmdKeyId = Optional.ofNullable(keycloakSession.getContext().getRealm().getAttribute("vcmdKeyId"));

        if (vcmdEnabled) {
            if (ldpProofType.isEmpty() || vcmdKeyPath.isEmpty() || vcmdKeyId.isEmpty()) {
                throw new IllegalArgumentException(
                        String.format("VCDM credentials are not properly configured. ldpProofType: %s, vcdmKeyPath: %s, vcmdKeyId: %s",
                                ldpProofType,
                                vcmdKeyPath,
                                vcmdKeyId));
            }
            try {
                signingServices.put(Format.LDP_VC, new LDSigningService(
                        new FileBasedKeyLoader(vcmdKeyPath.get()),
                        vcmdKeyId.get(),
                        clock,
                        ldpProofType.get(),
                        OBJECT_MAPPER));
            } catch (SigningServiceException e) {
                LOGGER.warn("Was not able to initialize LD SigningService, ld credentials are not supported.", e);
                throw new IllegalArgumentException("No valid ldp_vc signing configured.", e);

            }
        }
        // handle jwt-vcs
        boolean jwtVcEnabled = Optional.ofNullable(keycloakSession.getContext().getRealm().getAttribute("jwtVcEnabled")).map(Boolean::valueOf).orElse(false);
        Optional<String> jwtVcSignatureType = Optional.ofNullable(keycloakSession.getContext().getRealm().getAttribute("jwtVcSignatureType"));
        Optional<String> jwtVcKeyPath = Optional.ofNullable(keycloakSession.getContext().getRealm().getAttribute("jwtVcKeyPath"));
        Optional<String> jwtVcKeyId = Optional.ofNullable(keycloakSession.getContext().getRealm().getAttribute("jwtVcKeyId"));

        if (jwtVcEnabled) {
            if (jwtVcSignatureType.isEmpty() || jwtVcKeyPath.isEmpty() || jwtVcKeyId.isEmpty()) {
                throw new IllegalArgumentException(
                        String.format("VCDM credentials are not properly configured. jwtVcSignatureType: %s, jwtVcKeyPath: %s, jwtVcKeyId: %s",
                                jwtVcSignatureType,
                                jwtVcKeyPath,
                                jwtVcKeyId));
            }
            try {
                signingServices.put(Format.JWT_VC, new JwtSigningService(
                        new FileBasedKeyLoader(jwtVcKeyPath.get()),
                        jwtVcKeyId.get(),
                        clock,
                        jwtVcSignatureType.get()));
            } catch (SigningServiceException e) {
                LOGGER.warn("Was not able to initialize JWT-VC SigningService, jwt-vc credentials are not supported.", e);
                throw new IllegalArgumentException("No valid jwt-vc signing configured.", e);

            }
        }

        // handle jwt-vcs
        boolean sdJwtVcEnabled = Optional.ofNullable(keycloakSession.getContext().getRealm().getAttribute("sdJwtVcEnabled")).map(Boolean::valueOf).orElse(false);
        Optional<String> sdJwtVcSignatureType = Optional.ofNullable(keycloakSession.getContext().getRealm().getAttribute("sdJwtVcSignatureType"));
        Optional<String> sdJwtVcKeyPath = Optional.ofNullable(keycloakSession.getContext().getRealm().getAttribute("sdJwtVcKeyPath"));
        Optional<String> sdJwtVcKeyId = Optional.ofNullable(keycloakSession.getContext().getRealm().getAttribute("sdJwtVcKeyId"));
        int sdJwtDecoys = Optional.ofNullable(keycloakSession.getContext().getRealm().getAttribute("sdJwtDecoys")).map(Integer::valueOf).orElse(0);


        if (sdJwtVcEnabled) {
            if (sdJwtVcSignatureType.isEmpty() || sdJwtVcKeyPath.isEmpty() || sdJwtVcKeyId.isEmpty()) {
                throw new IllegalArgumentException(
                        String.format("SD-JWT credentials are not properly configured. sdJwtVcSignatureType: %s, sdJwtVcKeyPath: %s, sdJwtVcKeyId: %s",
                                sdJwtVcSignatureType,
                                sdJwtVcKeyPath,
                                sdJwtVcKeyId));
            }
            try {
                signingServices.put(Format.SD_JWT_VC, new SdJwtSigningService(
                        new FileBasedKeyLoader(sdJwtVcKeyPath.get()),
                        sdJwtVcKeyId.get(),
                        clock,
                        sdJwtVcSignatureType.get(),
                        OBJECT_MAPPER,
                        sdJwtDecoys));
            } catch (SigningServiceException e) {
                LOGGER.warn("Was not able to initialize SD-JWT-VC SigningService, sd-jwt-vc credentials are not supported.", e);
                throw new IllegalArgumentException("No valid sd-jwt-vc signing configured.", e);

            }
        }

        String issuerDid = Optional.ofNullable(keycloakSession.getContext().getRealm().getAttribute("issuerDid"))
                .orElseThrow(() -> new VCIssuerException("No issuerDid  configured."));


        return new OIDC4VPIssuerEndpoint(
                keycloakSession,
                issuerDid,
                signingServices,
                new AppAuthManager.BearerTokenAuthenticator(
                        keycloakSession),
                OBJECT_MAPPER, clock);
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
