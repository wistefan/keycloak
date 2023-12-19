package org.keycloak.protocol.oid4vc.issuance;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.validation.constraints.NotNull;
import jakarta.ws.rs.*;
import jakarta.ws.rs.core.Response;
import org.jboss.logging.Logger;
import org.keycloak.TokenVerifier;
import org.keycloak.common.VerificationException;
import org.keycloak.common.util.Time;
import org.keycloak.events.EventBuilder;
import org.keycloak.models.*;
import org.keycloak.protocol.oid4vc.OIDC4VPAbstractWellKnownProvider;
import org.keycloak.protocol.oid4vc.OIDC4VPClientRegistrationProvider;
import org.keycloak.protocol.oid4vc.OIDC4VPClientRegistrationProviderFactory;
import org.keycloak.protocol.oidc.utils.OAuth2Code;
import org.keycloak.protocol.oidc.utils.OAuth2CodeParser;
import org.keycloak.protocol.oid4vc.issuance.mappers.OIDC4VPMapper;
import org.keycloak.protocol.oid4vc.issuance.mappers.OIDC4VPMapperFactory;
import org.keycloak.protocol.oid4vc.model.*;
import org.keycloak.protocol.oid4vc.model.CredentialOfferURI;
import org.keycloak.protocol.oid4vc.model.CredentialRequest;
import org.keycloak.protocol.oid4vc.model.CredentialResponse;
import org.keycloak.protocol.oid4vc.model.CredentialsOffer;
import org.keycloak.protocol.oid4vc.model.ErrorResponse;
import org.keycloak.protocol.oid4vc.model.Format;
import org.keycloak.protocol.oid4vc.model.PreAuthorized;
import org.keycloak.protocol.oid4vc.model.PreAuthorizedGrant;
import org.keycloak.protocol.oid4vc.model.SupportedCredential;
import org.keycloak.protocol.oid4vc.model.vcdm.LdProof;
import org.keycloak.protocol.oid4vc.issuance.signing.*;
import org.keycloak.representations.JsonWebToken;
import org.keycloak.services.managers.AppAuthManager;
import org.keycloak.services.managers.AuthenticationManager;

import java.net.URI;
import java.time.Clock;
import java.util.*;
import java.util.stream.Collectors;

import static org.keycloak.protocol.oid4vc.OIDC4VPClientRegistrationProvider.VC_TYPES_PREFIX;
import static org.keycloak.protocol.oid4vc.model.Format.*;

/**
 * Realm-Resource to provide functionality for issuing VerifiableCredentials to users, depending on their roles in
 * registered OIDC4VP clients
 */
public class OIDC4VPIssuerEndpoint {

    private static final Logger LOGGER = Logger.getLogger(OIDC4VPIssuerEndpoint.class);

    public static final String CREDENTIAL_PATH = "credential";
    public static final String TYPE_VERIFIABLE_CREDENTIAL = "VerifiableCredential";
    public static final String GRANT_TYPE_PRE_AUTHORIZED_CODE = "urn:ietf:params:oauth:grant-type:pre-authorized_code";
    private static final String ACCESS_CONTROL_HEADER = "Access-Control-Allow-Origin";

    private final KeycloakSession session;
    private final AppAuthManager.BearerTokenAuthenticator bearerTokenAuthenticator;
    private final ObjectMapper objectMapper;
    private final Clock clock;

    private final String issuerDid;

    private LDSigningService ldSigningService;
    private JwtSigningService jwtSigningService;
    private SdJwtSigningService sdJwtSigningService;

    private final Map<Format, VCSigningService> signingServices;

    public OIDC4VPIssuerEndpoint(KeycloakSession session,
                                 String issuerDid,
                                 Map<Format, VCSigningService> signingServices,
                                 AppAuthManager.BearerTokenAuthenticator authenticator,
                                 ObjectMapper objectMapper, Clock clock) {
        this.session = session;
        this.bearerTokenAuthenticator = authenticator;
        this.objectMapper = objectMapper;
        this.clock = clock;
        this.issuerDid = issuerDid;
        this.signingServices = signingServices;

    }

    /**
     * Provides URI to the OIDC4VCI compliant credentials offer
     */
    @GET
    @Path("credential-offer-uri")
    public Response getCredentialOfferURI(@QueryParam("credentialId") String vcId) {

        Map<String, SupportedCredential> credentialsMap = OIDC4VPAbstractWellKnownProvider
                .getSupportedCredentials(session.getContext()).stream()
                .collect(Collectors.toMap(SupportedCredential::getId, sc -> sc, (sc1, sc2) -> sc1));

        LOGGER.debugf("Get an offer for %s", vcId);
        if (!credentialsMap.containsKey(vcId)) {
            LOGGER.warnf("No credential with id %s exists.", vcId);
            LOGGER.debugf("Supported credentials are %s.", credentialsMap);
            throw new BadRequestException(getErrorResponse(ErrorResponse.ErrorEnum.INVALID_REQUEST));
        }
        SupportedCredential supportedCredential = credentialsMap.get(vcId);
        var format = supportedCredential.getFormat();

        // check that the user is allowed to get such credential
        supportedCredential.getTypes()
                .forEach(type -> getClientsOfType(type, format));

        String nonce = generateAuthorizationCode();

        AuthenticationManager.AuthResult authResult = getAuthResult();
        UserSessionModel userSessionModel = getUserSessionModel();

        AuthenticatedClientSessionModel clientSession = userSessionModel.
                getAuthenticatedClientSessionByClient(
                        authResult.getClient().getId());
        try {
            clientSession.setNote(nonce, objectMapper.writeValueAsString(supportedCredential));
        } catch (JsonProcessingException e) {
            LOGGER.errorf("Could not convert POJO to JSON: %s", e.getMessage());
            throw new BadRequestException(getErrorResponse(ErrorResponse.ErrorEnum.INVALID_REQUEST));
        }

        CredentialOfferURI credentialOfferURI = new CredentialOfferURI();
        credentialOfferURI.setIssuer(OIDC4VPAbstractWellKnownProvider.getIssuer(session.getContext()));
        credentialOfferURI.setNonce(nonce);

        LOGGER.debugf("Responding with nonce: %s", nonce);
        return Response.ok()
                .entity(credentialOfferURI)
                .header(ACCESS_CONTROL_HEADER, "*")
                .build();

    }

    /**
     * Provides an OIDC4VCI compliant credentials offer
     */
    @GET
    @Path("credential-offer/{nonce}")
    public Response getCredentialOffer(@PathParam("nonce") String nonce) {

        OAuth2CodeParser.ParseResult result = parseNonce(nonce);

        SupportedCredential offeredCredential;
        try {
            offeredCredential = objectMapper.readValue(result.getClientSession().getNote(nonce),
                    SupportedCredential.class);
            LOGGER.debugf("Creating an offer for %s - %s", offeredCredential.getTypes(),
                    offeredCredential.getFormat());
            result.getClientSession().removeNote(nonce);
        } catch (JsonProcessingException e) {
            LOGGER.errorf("Could not convert JSON to POJO: %s", e);
            throw new BadRequestException(getErrorResponse(ErrorResponse.ErrorEnum.INVALID_REQUEST));
        }

        String preAuthorizedCode = generateAuthorizationCodeForClientSession(result.getClientSession());
        CredentialsOffer theOffer = new CredentialsOffer()
                .credentialIssuer(OIDC4VPAbstractWellKnownProvider.getIssuer(session.getContext()))
                .credentials(List.of(offeredCredential))
                .grants(new PreAuthorizedGrant().
                        urnColonIetfColonParamsColonOauthColonGrantTypeColonPreAuthorizedCode(
                                new PreAuthorized().preAuthorizedCode(preAuthorizedCode)
                                        .userPinRequired(false)));

        LOGGER.debugf("Responding with offer: %s", theOffer);
        return Response.ok()
                .entity(theOffer)
                .header(ACCESS_CONTROL_HEADER, "*")
                .build();
    }

    /**
     * Options endpoint to serve the cors-preflight requests.
     * Since we cannot know the address of the requesting wallets in advance, we have to accept all origins.
     */
    @OPTIONS
    @Path("{any: .*}")
    public Response optionCorsResponse() {
        return Response.ok().header(ACCESS_CONTROL_HEADER, "*")
                .header("Access-Control-Allow-Methods", "POST,GET,OPTIONS")
                .header("Access-Control-Allow-Headers", "Content-Type,Authorization")
                .build();
    }

    /**
     * Returns a verifiable credential of the given type, containing the information and roles assigned to the
     * authenticated user.
     * In order to support the often used retrieval method by wallets, the token can also be provided as a
     * query-parameter. If the parameter is empty, the token is taken from the authorization-header.
     *
     * @param vcType type of the VerifiableCredential to be returend.
     * @param token  optional JWT to be used instead of retrieving it from the header.
     * @return the vc.
     */
    @GET
    @Path("/")
    public Response issueVerifiableCredential(@QueryParam("type") String vcType, @QueryParam("token") String
            token) {
        LOGGER.debugf("Get a VC of type %s. Token parameter is %s.", vcType, token);
        if (token != null) {
            // authenticate with the token
            bearerTokenAuthenticator.setTokenString(token);
        }
        return Response.ok()
                .entity(getCredential(vcType, LDP_VC))
                .header(ACCESS_CONTROL_HEADER, "*")
                .build();
    }

    /**
     * Requests a credential from the issuer
     */
    @POST
    @Path(CREDENTIAL_PATH)
    public Response requestCredential(
            CredentialRequest credentialRequestVO) {
        LOGGER.debugf("Received credentials request %s.", credentialRequestVO);

        List<String> types = new ArrayList<>(Objects.requireNonNull(Optional.ofNullable(credentialRequestVO.getTypes())
                .orElseGet(() -> {
                    try {
                        return objectMapper.readValue(credentialRequestVO.getType(), new TypeReference<>() {
                        });
                    } catch (JsonProcessingException e) {
                        LOGGER.warnf("Was not able to read the type parameter: %s", credentialRequestVO.getType(), e);
                        return null;
                    }
                })));

        // remove the static type
        types.remove(TYPE_VERIFIABLE_CREDENTIAL);

        if (types.size() != 1) {
            LOGGER.infof("Credential request contained multiple types. Req: %s", credentialRequestVO);
            throw new BadRequestException(getErrorResponse(ErrorResponse.ErrorEnum.INVALID_REQUEST));
        }
        // verify the proof
//		Optional.ofNullable(credentialRequestVO.getProof()).ifPresent(this::verifyProof);

        Format requestedFormat = credentialRequestVO.getFormat();

        // TODO: check if there can be more
        String vcType = types.get(0);

        var responseVO = new CredentialResponse();
        // keep the originally requested here.
        responseVO.format(credentialRequestVO.getFormat());

        Object theCredential = getCredential(vcType, credentialRequestVO.getFormat());
        switch (requestedFormat) {
            case LDP_VC, JWT_VC, SD_JWT_VC -> responseVO.setCredential(theCredential);
            default -> throw new BadRequestException(
                    getErrorResponse(ErrorResponse.ErrorEnum.UNSUPPORTED_CREDENTIAL_TYPE));
        }
        return Response.ok().entity(responseVO)
                .header(ACCESS_CONTROL_HEADER, "*").build();
    }

    // return the current usersession model
    private UserSessionModel getUserSessionModel() {
        return getAuthResult(
                new BadRequestException(getErrorResponse(ErrorResponse.ErrorEnum.INVALID_TOKEN))).getSession();
    }

    private AuthenticationManager.AuthResult getAuthResult() {
        return getAuthResult(new BadRequestException(getErrorResponse(ErrorResponse.ErrorEnum.INVALID_TOKEN)));
    }

    // get the auth result from the authentication manager
    private AuthenticationManager.AuthResult getAuthResult(WebApplicationException errorResponse) {
        AuthenticationManager.AuthResult authResult = bearerTokenAuthenticator.authenticate();
        if (authResult == null) {
            throw errorResponse;
        }
        return authResult;
    }

    protected Object getCredential(String vcType, Format format) {
        // do first to fail fast on auth
        UserSessionModel userSessionModel = getUserSessionModel();
        List<ClientModel> clients = getClientsOfType(vcType, format);
        List<OIDC4VPMapper> protocolMappers = getProtocolMappers(clients)
                .stream()
                .map(OIDC4VPMapperFactory::createOIDC4VPMapper)
                .toList();

        var credentialToSign = getVCToSign(protocolMappers, vcType, userSessionModel);

        return switch (format) {
            case LDP_VC -> {
                if (signingServices.containsKey(LDP_VC)) {
                    yield signingServices.get(LDP_VC).signCredential(credentialToSign);
                }
                throw new IllegalArgumentException(
                        String.format("Requested format %s is not supported.", format));
            }
            case JWT_VC -> {
                if (signingServices.containsKey(JWT_VC)) {
                    yield signingServices.get(JWT_VC).signCredential(credentialToSign);
                }
                throw new IllegalArgumentException(
                        String.format("Requested format %s is not supported.", format));
            }
            case SD_JWT_VC -> {
                if (signingServices.containsKey(SD_JWT_VC)) {
                    yield signingServices.get(SD_JWT_VC).signCredential(credentialToSign);
                }
                throw new IllegalArgumentException(
                        String.format("Requested format %s is not supported.", format));
            }
        };
    }

    private List<ProtocolMapperModel> getProtocolMappers(List<ClientModel> clientModels) {
        return clientModels.stream()
                .flatMap(ProtocolMapperContainerModel::getProtocolMappersStream)
                .toList();

    }

    private OAuth2CodeParser.ParseResult parseNonce(String nonce) throws BadRequestException {
        EventBuilder eventBuilder = new EventBuilder(session.getContext().getRealm(), session,
                session.getContext().getConnection());
        OAuth2CodeParser.ParseResult result = OAuth2CodeParser.parseCode(session, nonce,
                session.getContext().getRealm(),
                eventBuilder);
        if (result.isExpiredCode() || result.isIllegalCode()) {
            throw new BadRequestException(getErrorResponse(ErrorResponse.ErrorEnum.INVALID_TOKEN));
        }
        return result;
    }

    private String generateAuthorizationCode() {
        AuthenticationManager.AuthResult authResult = getAuthResult();
        UserSessionModel userSessionModel = getUserSessionModel();
        AuthenticatedClientSessionModel clientSessionModel = userSessionModel.
                getAuthenticatedClientSessionByClient(authResult.getClient().getId());
        return generateAuthorizationCodeForClientSession(clientSessionModel);
    }

    private String generateAuthorizationCodeForClientSession(AuthenticatedClientSessionModel clientSessionModel) {
        int expiration = Time.currentTime() + clientSessionModel.getUserSession().getRealm().getAccessCodeLifespan();

        String codeId = UUID.randomUUID().toString();
        String nonce = UUID.randomUUID().toString();
        OAuth2Code oAuth2Code = new OAuth2Code(codeId, expiration, nonce, null, null, null, null,
                clientSessionModel.getUserSession().getId());

        return OAuth2CodeParser.persistCode(session, clientSessionModel, oAuth2Code);
    }

    private Response getErrorResponse(ErrorResponse.ErrorEnum errorType) {
        var errorResponse = new ErrorResponse();
        errorResponse.setError(errorType);
        return Response.status(Response.Status.BAD_REQUEST).entity(errorResponse).build();
    }

    @NotNull
    private List<ClientModel> getClientsOfType(String vcType, Format format) {
        LOGGER.debugf("Retrieve all clients of type %s, supporting format %s", vcType, format.toString());

        List<String> formatStrings = switch (format) {
            case LDP_VC -> List.of(LDP_VC.toString());
            case JWT_VC -> List.of(JWT_VC.toString());
            case SD_JWT_VC -> List.of(SD_JWT_VC.toString());

        };

        Optional.ofNullable(vcType).filter(type -> !type.isEmpty()).orElseThrow(() -> {
            LOGGER.info("No VC type was provided.");
            return new BadRequestException("No VerifiableCredential-Type was provided in the request.");
        });

        String prefixedType = String.format("%s%s", VC_TYPES_PREFIX, vcType);
        LOGGER.infof("Looking for client supporting %s with format %s", prefixedType, formatStrings);
        List<ClientModel> vcClients = getClientModelsFromSession().stream()
                .filter(clientModel -> Optional.ofNullable(clientModel.getAttributes())
                        .filter(attributes -> attributes.containsKey(prefixedType))
                        .filter(attributes -> formatStrings.stream()
                                .anyMatch(formatString -> Arrays.asList(attributes.get(prefixedType).split(","))
                                        .contains(formatString)))
                        .isPresent())
                .toList();

        if (vcClients.isEmpty()) {
            LOGGER.infof("No OIDC4VP-Client supporting type %s registered.", vcType);
            throw new BadRequestException(getErrorResponse(ErrorResponse.ErrorEnum.UNSUPPORTED_CREDENTIAL_TYPE));
        }
        return vcClients;
    }

    @NotNull
    private List<ClientModel> getClientModelsFromSession() {
        return session.clients().getClientsStream(session.getContext().getRealm())
                .filter(clientModel -> clientModel.getProtocol() != null)
                .filter(clientModel -> clientModel.getProtocol()
                        .equals(OIDC4VPClientRegistrationProviderFactory.PROTOCOL_ID))
                .toList();
    }

    @NotNull
    private VerifiableCredential getVCToSign(List<OIDC4VPMapper> protocolMappers, String vcType,
                                             UserSessionModel userSessionModel) {

        var vc = new VerifiableCredential();

        // set the required claims
        vc.setIssuer(URI.create(issuerDid));
        vc.setIssuanceDate(Date.from(clock.instant()));
        vc.addType(vcType);
        Map<String, Object> subjectClaims = new HashMap<>();

        protocolMappers
                .forEach(mapper -> mapper.setClaimsForSubject(subjectClaims, userSessionModel));

        LOGGER.infof("Will set %s", subjectClaims);
        subjectClaims.entrySet().stream().forEach(entry -> vc.getCredentialSubject().setClaims(entry.getKey(), entry.getValue()));
        // use the mappers after the default
        protocolMappers
                .forEach(mapper -> mapper.setClaimsForCredential(vc, userSessionModel));
        if (vc.getContext() == null || vc.getContext().isEmpty()) {
            // add default
            vc.setContext(List.of("https://www.w3.org/2018/credentials/v1"));
        }

        if (vc.getId() == null && vc.getAdditionalProperties().get("id") == null) {
            vc.setId(URI.create(String.format("uri:uuid:%s", UUID.randomUUID())));
        }
        if (vc.getCredentialSubject().getId() == null && vc.getCredentialSubject().getClaims().get("id") == null) {
            vc.getCredentialSubject().setId(String.format("uri:uuid:%s", UUID.randomUUID()));
        }
        return vc;
    }

    private static class ClientRoleModel {
        private final String clientId;
        private final List<RoleModel> roleModels;

        public ClientRoleModel(String clientId, List<RoleModel> roleModels) {
            this.clientId = clientId;
            this.roleModels = roleModels;
        }

        public String getClientId() {
            return clientId;
        }

        public List<RoleModel> getRoleModels() {
            return roleModels;
        }
    }
}

