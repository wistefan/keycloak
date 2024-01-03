package org.keycloak.protocol.oid4vc.issuance;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.MapperFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.databind.json.JsonMapper;
import jakarta.ws.rs.WebApplicationException;
import jakarta.ws.rs.core.Response;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.keycloak.TokenVerifier;
import org.keycloak.common.VerificationException;
import org.keycloak.models.*;
import org.keycloak.protocol.oid4vc.ExpectedResult;
import org.keycloak.protocol.oid4vc.OID4VPClientRegistrationProviderFactory;
import org.keycloak.protocol.oid4vc.issuance.mappers.*;
import org.keycloak.protocol.oid4vc.issuance.signing.JwtSigningService;
import org.keycloak.protocol.oid4vc.issuance.signing.LDSigningService;
import org.keycloak.protocol.oid4vc.issuance.signing.SdJwtSigningService;
import org.keycloak.protocol.oid4vc.model.*;
import org.keycloak.protocol.oid4vc.model.ErrorResponse;
import org.keycloak.protocol.oid4vc.model.Format;
import org.keycloak.protocol.oid4vc.model.SupportedCredential;
import org.keycloak.representations.JsonWebToken;
import org.keycloak.services.managers.AppAuthManager;
import org.keycloak.services.managers.AuthenticationManager;

import java.security.Security;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneId;
import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.*;
import static org.keycloak.protocol.oid4vc.issuance.signing.SigningServiceTest.*;
import static org.mockito.Matchers.*;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;


public class OID4VPIssuerEndpointTest {

    private static final String ISSUER_DID = "did:key:test";

    private final ObjectMapper OBJECT_MAPPER = JsonMapper.builder()
            .configure(SerializationFeature.ORDER_MAP_ENTRIES_BY_KEYS, true)
            .configure(MapperFeature.SORT_PROPERTIES_ALPHABETICALLY, true).build();

    private KeycloakSession keycloakSession = mock(KeycloakSession.class);
    ;
    private AppAuthManager.BearerTokenAuthenticator bearerTokenAuthenticator;

    private OID4VPIssuerEndpoint testEndpoint;

    private Clock fixedClock = Clock.fixed(Instant.parse("2022-11-10T17:11:09.00Z"),
            ZoneId.of("Europe/Paris"));

    private KeycloakContext context;


    @BeforeEach
    public void setUp() {

        Security.addProvider(new BouncyCastleProvider());
        this.keycloakSession = mock(KeycloakSession.class);
        this.context = mock(KeycloakContext.class);
        KeyManager keyManager = mock(KeyManager.class);
        RealmModel realmModel = mock(RealmModel.class);
        when(keycloakSession.keys()).thenReturn(keyManager);
        when(keycloakSession.getContext()).thenReturn(context);
        when(context.getRealm()).thenReturn(realmModel);
        when(keyManager.getKey(any(), eq("ec-key"), any(), anyString())).thenReturn(getEd25519Key("ec-key"));
        when(keyManager.getKey(any(), eq("rsa-key"), any(), anyString())).thenReturn(getRsaKey("rsa-key"));
        var ldpSigningService = new LDSigningService(keycloakSession, "ec-key", fixedClock, "Ed25519Signature2018", OBJECT_MAPPER);
        var jwtSigningService = new JwtSigningService(keycloakSession, "rsa-key", fixedClock, "RS256", ISSUER_DID);
        var sdJwtSigningService = new SdJwtSigningService(keycloakSession, "rsa-key", fixedClock, "RS256", OBJECT_MAPPER, 3, ISSUER_DID);


        this.bearerTokenAuthenticator = mock(AppAuthManager.BearerTokenAuthenticator.class);
        this.testEndpoint = new OID4VPIssuerEndpoint(
                keycloakSession,
                ISSUER_DID,
                Map.of(Format.LDP_VC, ldpSigningService, Format.JWT_VC, jwtSigningService, Format.SD_JWT_VC, sdJwtSigningService),
                bearerTokenAuthenticator, OBJECT_MAPPER, fixedClock);
    }

    @Test
    public void testGetVCUnauthorized() {
        RealmModel realmModel = mock(RealmModel.class);
        when(keycloakSession.getContext()).thenReturn(context);
        when(context.getRealm()).thenReturn(realmModel);

        when(bearerTokenAuthenticator.authenticate()).thenReturn(null);

        try {
            testEndpoint.issueVerifiableCredential(ISSUER_DID, "MyVC");
            fail("VCs should only be accessible for authorized users.");
        } catch (WebApplicationException e) {
            assertEquals(Response.Status.BAD_REQUEST.getStatusCode(), e.getResponse().getStatus(),
                    "The response should be a 400.");
            ErrorResponse er = OBJECT_MAPPER.convertValue(e.getResponse().getEntity(), ErrorResponse.class);
            assertEquals(ErrorType.INVALID_TOKEN.getValue(), er.getError().value(),
                    "The response should have been denied because of the invalid token.");
        }
    }

    @ParameterizedTest
    @MethodSource("provideTypesAndClients")
    public void testGetVCNoSuchType(Stream<ClientModel> clientModelStream,
                                    ExpectedResult<Set<SupportedCredential>> ignored) {
        AuthenticationManager.AuthResult authResult = mock(AuthenticationManager.AuthResult.class);
        UserModel userModel = mock(UserModel.class);
        RealmModel realmModel = mock(RealmModel.class);
        ClientProvider clientProvider = mock(ClientProvider.class);

        when(bearerTokenAuthenticator.authenticate()).thenReturn(authResult);
        when(authResult.getUser()).thenReturn(userModel);
        when(keycloakSession.getContext()).thenReturn(context);
        when(context.getRealm()).thenReturn(realmModel);
        when(keycloakSession.clients()).thenReturn(clientProvider);
        when(clientProvider.getClientsStream(any())).thenReturn(clientModelStream);

        try {
            testEndpoint.issueVerifiableCredential(ISSUER_DID, "MyNonExistentType");
            fail("Not found types should be a 400");
        } catch (WebApplicationException e) {
            assertEquals(Response.Status.BAD_REQUEST.getStatusCode(), e.getResponse().getStatus(),
                    "Not found types should be a 400");
            ErrorResponse er = OBJECT_MAPPER.convertValue(e.getResponse().getEntity(), ErrorResponse.class);
            assertEquals(ErrorType.UNSUPPORTED_CREDENTIAL_TYPE.getValue(), er.getError().value(),
                    "The response should have been denied because of the unsupported type.");
        }
    }

    @ParameterizedTest
    @MethodSource("provideUserAndClients")
    public void testGetCredential(UserModel userModel, Stream<ClientModel> clientModelStream,
                                  Map<ClientModel, Stream<RoleModel>> roleModelStreamMap,
                                  ExpectedResult<CredentialSubject> expectedResult, Format requestedFormat)
            throws JsonProcessingException, VerificationException {
        List<ClientModel> clientModels = clientModelStream.toList();

        AuthenticationManager.AuthResult authResult = mock(AuthenticationManager.AuthResult.class);
        RealmModel realmModel = mock(RealmModel.class);
        ClientProvider clientProvider = mock(ClientProvider.class);

        UserSessionModel userSessionModel = mock(UserSessionModel.class);
        when(userSessionModel.getRealm()).thenReturn(realmModel);
        when(userSessionModel.getUser()).thenReturn(userModel);
        clientModels.forEach(cm -> when(realmModel.getClientByClientId(eq(cm.getClientId()))).thenReturn(cm));
        when(realmModel.getClientsStream()).thenReturn(clientModels.stream());

        when(bearerTokenAuthenticator.authenticate()).thenReturn(authResult);

        when(authResult.getUser()).thenReturn(userModel);
        when(authResult.getSession()).thenReturn(userSessionModel);

        when(keycloakSession.getContext()).thenReturn(context);
        when(context.getRealm()).thenReturn(realmModel);

        when(keycloakSession.clients()).thenReturn(clientProvider);
        when(clientProvider.getClientsStream(any())).thenReturn(clientModels.stream());

        when(userModel.getClientRoleMappingsStream(any())).thenAnswer(i -> roleModelStreamMap.get(i.getArguments()[0]));
        Object credential = testEndpoint.getCredential("MyType", requestedFormat);
        switch (requestedFormat) {
            case LDP_VC -> {
                VerifiableCredential verifiableCredential = OBJECT_MAPPER.convertValue(credential, VerifiableCredential.class);
                verifyLDCredential(expectedResult, verifiableCredential);
            }
            case JWT_VC -> verifyJWTCredential(expectedResult, (String) credential);
            case SD_JWT_VC -> verifySdJwtCredential(expectedResult, (String) credential);
        }
    }


    private void verifySdJwtCredential(ExpectedResult<CredentialSubject> expectedResult, String actualResult)
            throws VerificationException, JsonProcessingException {
        String[] splittedToken = actualResult.split("\\.");
        // the first 3 elements should make the jwt
        assertTrue(splittedToken.length >= 3, "It should contain at least 3 parts that make up the jwt");
        var jwt = new StringJoiner(".")
                .add(splittedToken[0])
                .add(splittedToken[1])
                .add(splittedToken[2])
                .toString();
        TokenVerifier<JsonWebToken> verifier = TokenVerifier.create(jwt, JsonWebToken.class);
        JsonWebToken theJWT = verifier.getToken();
        assertEquals(ISSUER_DID, theJWT.getIssuer(), "The issuer should be properly set.");
        assertNotNull(theJWT.getSubject(), "A subject should be set.");
        assertNotNull(theJWT.getOtherClaims().get("_sd_alg"), "The sd-algorithm should be set.");
        assertNotNull(theJWT.getOtherClaims().get("vct"), "The type should be set.");
    }


    private void verifyJWTCredential(ExpectedResult<CredentialSubject> expectedResult, String actualResult)
            throws VerificationException, JsonProcessingException {
        TokenVerifier<JsonWebToken> verifier = TokenVerifier.create(actualResult, JsonWebToken.class);
        JsonWebToken theJWT = verifier.getToken();
        assertEquals(ISSUER_DID, theJWT.getIssuer(), "The issuer should be properly set.");
        assertNotNull(theJWT.getSubject(), "A subject should be set.");
        assertNotNull(theJWT.getId(), "The jwt should have an id.");

        VerifiableCredential theVC = OBJECT_MAPPER.convertValue(theJWT.getOtherClaims().get("vc"), VerifiableCredential.class);

        assertNotNull(theVC, "The vc should be part of the jwt.");
        List credentialType = (List) theVC.getType();
        assertEquals(2, credentialType.size(), "Both types should be included.");
        assertTrue(credentialType.contains("MyType") && credentialType.contains("VerifiableCredential"),
                "The correct types should be included.");


        verifySubject(expectedResult, expectedResult.getExpectedResult(), theVC.getCredentialSubject());

    }

    @ParameterizedTest
    @MethodSource("provideUserAndClientsLDP")
    public void testGetVC(UserModel userModel, Stream<ClientModel> clientModelStream,
                          Map<ClientModel, Stream<RoleModel>> roleModelStreamMap,
                          ExpectedResult<CredentialSubject> expectedResult) throws JsonProcessingException {
        List<ClientModel> clientModels = clientModelStream.toList();

        AuthenticationManager.AuthResult authResult = mock(AuthenticationManager.AuthResult.class);
        RealmModel realmModel = mock(RealmModel.class);
        ClientProvider clientProvider = mock(ClientProvider.class);
        UserSessionModel userSessionModel = mock(UserSessionModel.class);
        when(userSessionModel.getRealm()).thenReturn(realmModel);
        when(userSessionModel.getUser()).thenReturn(userModel);
        clientModels.forEach(cm -> when(realmModel.getClientByClientId(eq(cm.getClientId()))).thenReturn(cm));

        when(bearerTokenAuthenticator.authenticate()).thenReturn(authResult);
        when(authResult.getUser()).thenReturn(userModel);
        when(authResult.getSession()).thenReturn(userSessionModel);
        when(keycloakSession.getContext()).thenReturn(context);
        when(context.getRealm()).thenReturn(realmModel);
        when(keycloakSession.clients()).thenReturn(clientProvider);
        // use then to open a new stream on each invocation
        when(clientProvider.getClientsStream(any())).then(f -> clientModels.stream());

        when(userModel.getClientRoleMappingsStream(any())).thenAnswer(i -> roleModelStreamMap.get(i.getArguments()[0]));

        VerifiableCredential credentialVO = OBJECT_MAPPER.convertValue(
                testEndpoint.issueVerifiableCredential("MyType", "myToken").getEntity(),
                VerifiableCredential.class);

        verifyLDCredential(expectedResult, credentialVO);
    }


    private void verifyLDCredential(ExpectedResult<CredentialSubject> expectedResult, VerifiableCredential credentialVO)
            throws JsonProcessingException {
        assertEquals(Date.from(fixedClock.instant()), credentialVO.getIssuanceDate(),
                "The issuance date should be correctly set.");
        assertNotNull(credentialVO.getContext(), "The context should be set on an ld-credential.");
        assertNotNull(credentialVO.getProof(), "The proof should be included.");
        assertNotNull(credentialVO.getId(), "The credential should have an id.");
        List credentialType = (List) credentialVO.getType();
        assertEquals(2, credentialType.size(), "Both types should be included.");
        assertTrue(credentialType.contains("MyType") && credentialType.contains("VerifiableCredential"),
                "The correct types should be included.");

        assertEquals(ISSUER_DID, credentialVO.getIssuer().toString(), "The correct issuer should be set.");

        CredentialSubject retrievedSubject = credentialVO.getCredentialSubject();
        assertNotNull(retrievedSubject.getId(), "The id should have been set.");
        // remove the id, since its randomly generated.
        retrievedSubject.setId(null);

        verifySubject(expectedResult, expectedResult.getExpectedResult(), retrievedSubject);
    }

    private void verifySubject(ExpectedResult<CredentialSubject> expectedResult, CredentialSubject expectedCredentialSubject, CredentialSubject retrievedSubject)
            throws JsonProcessingException {
        verifyRoles(expectedResult.getMessage(), expectedCredentialSubject, retrievedSubject);
        // roles are checked, can be removed to not interfer with next checks.
        expectedCredentialSubject.setClaims("roles", null);
        retrievedSubject.setClaims("roles", null);

        // is generated, thus remove
        retrievedSubject.setId(null);
        String expectedJson = OBJECT_MAPPER.writeValueAsString(expectedCredentialSubject);
        String retrievedJson = OBJECT_MAPPER.writeValueAsString(retrievedSubject);
        // we compare the json, to prevent order issues.
        assertEquals(expectedJson, retrievedJson, expectedResult.getMessage());
    }

    private void verifyRoles(String message, CredentialSubject expectedCredentialSubject, CredentialSubject retrievedSubject) {
        Set<Role> retrievedRoles = OBJECT_MAPPER.convertValue(retrievedSubject.getClaims().get("roles"),
                new TypeReference<Set<Role>>() {
                });
        Set<Role> expectedRoles = OBJECT_MAPPER.convertValue(expectedCredentialSubject.getClaims().get("roles"),
                new TypeReference<Set<Role>>() {
                });
        assertEquals(expectedRoles, retrievedRoles, message);
    }

    private static Arguments getArguments(UserModel um, Map<ClientModel, List<RoleModel>> clients,
                                          ExpectedResult expectedResult) {
        return Arguments.of(um,
                clients.keySet().stream(),
                clients.entrySet()
                        .stream()
                        .filter(e -> e.getValue() != null)
                        .collect(
                                Collectors.toMap(Map.Entry::getKey, e -> ((List) e.getValue()).stream(),
                                        (e1, e2) -> e1)),
                expectedResult);
    }

    private static Stream<Arguments> provideUserAndClients() {
        return Stream.concat(Stream.concat(provideUserAndClientsLDP().map(a -> {
                    var argObjects = new ArrayList<>(Arrays.asList(a.get()));
                    argObjects.add(Format.LDP_VC);
                    return Arguments.of(argObjects.toArray());
                }),
                provideUserAndClientsJWT(Format.JWT_VC).map(a -> {
                    var argObjects = new ArrayList<>(Arrays.asList(a.get()));
                    argObjects.add(Format.JWT_VC);
                    return Arguments.of(argObjects.toArray());
                })), provideUserAndClientsJWT(Format.SD_JWT_VC).map(a -> {
            var argObjects = new ArrayList<>(Arrays.asList(a.get()));
            argObjects.add(Format.SD_JWT_VC);
            return Arguments.of(argObjects.toArray());
        }));
    }

    private static CredentialSubject getCredentialSubject(Map<String, Object> claims) {
        CredentialSubject credentialSubject = new CredentialSubject();
        claims.entrySet().stream().forEach(e -> credentialSubject.setClaims(e.getKey(), e.getValue()));
        return credentialSubject;
    }

    private static Stream<Arguments> provideUserAndClientsJWT(Format theFormat) {
        return Stream.of(
                getArguments(getUserModel("e@mail.org", "Happy", "User"),
                        Map.of(getOidc4VpClient("did:key:1",
                                        Map.of("vctypes_MyType", theFormat.toString()),
                                        List.of("MyRole"),
                                        List.of("MyType", "VerifiableCredential"),
                                        theFormat == Format.JWT_VC),
                                List.of(getRoleModel("MyRole"))),
                        new ExpectedResult<>(
                                getCredentialSubject(
                                        Map.of("email", "e@mail.org", "familyName", "User", "firstName", "Happy", "roles",
                                                Set.of(new Role(Set.of("MyRole"), "did:key:1")))),
                                "A valid Credential should have been returned.")
                ),
                getArguments(getUserModel("e@mail.org", null, "User"),
                        Map.of(getOidc4VpClient("did:key:1",
                                        Map.of("vctypes_MyType", theFormat.toString()),
                                        List.of("MyRole"),
                                        List.of("MyType", "VerifiableCredential"),
                                        theFormat == Format.JWT_VC),
                                List.of(getRoleModel("MyRole"))),
                        new ExpectedResult<>(
                                getCredentialSubject(
                                        Map.of("email", "e@mail.org", "familyName", "User", "roles",
                                                Set.of(new Role(Set.of("MyRole"), "did:key:1")))),
                                "A valid Credential should have been returned.")
                ),
                getArguments(
                        getUserModel("e@mail.org", null, null),
                        Map.of(getOidc4VpClient("did:key:1",
                                        Map.of("vctypes_MyType", theFormat.toString()),
                                        List.of("MyRole"),
                                        List.of("MyType", "VerifiableCredential"),
                                        theFormat == Format.JWT_VC),
                                List.of(getRoleModel("MyRole"))),
                        new ExpectedResult<>(
                                getCredentialSubject(
                                        Map.of("email", "e@mail.org", "roles",
                                                Set.of(new Role(Set.of("MyRole"), "did:key:1")))),
                                "A valid Credential should have been returned.")
                ),
                getArguments(
                        getUserModel(null, null, null),
                        Map.of(getOidc4VpClient("did:key:1",
                                        Map.of("vctypes_MyType", theFormat.toString()),
                                        List.of("MyRole"),
                                        List.of("MyType", "VerifiableCredential"),
                                        theFormat == Format.JWT_VC),
                                List.of(getRoleModel("MyRole"))),
                        new ExpectedResult<>(
                                getCredentialSubject(
                                        Map.of("roles",
                                                Set.of(new Role(Set.of("MyRole"), "did:key:1")))),
                                "A valid Credential should have been returned.")
                ),
                getArguments(
                        getUserModel(null, null, null),
                        Map.of(getOidc4VpClient("did:key:1",
                                        Map.of("vctypes_MyType", theFormat.toString()),
                                        List.of("MyRole", "MySecondRole"),
                                        List.of("MyType", "VerifiableCredential"),
                                        theFormat == Format.JWT_VC),
                                List.of(getRoleModel("MyRole"), getRoleModel("MySecondRole"))),
                        new ExpectedResult<>(
                                getCredentialSubject(
                                        Map.of("roles",
                                                Set.of(new Role(Set.of("MyRole", "MySecondRole"), "did:key:1")))),
                                "Multiple roles should be included")
                ),
                getArguments(
                        getUserModel(null, null, null),
                        Map.of(getOidc4VpClient("did:key:1",
                                        Map.of("vctypes_MyType", theFormat.toString()),
                                        List.of("MyRole", "MySecondRole"),
                                        List.of("MyType", "VerifiableCredential"),
                                        theFormat == Format.JWT_VC),
                                List.of(getRoleModel("MyRole"))),
                        new ExpectedResult<>(
                                getCredentialSubject(
                                        Map.of("roles",
                                                Set.of(new Role(Set.of("MyRole"), "did:key:1")))),
                                "Only assigned roles should be included.")
                ),
                getArguments(
                        getUserModel(null, null, null),
                        Map.of(getOidc4VpClient("did:key:1",
                                        Map.of("vctypes_MyType", theFormat.toString()),
                                        List.of("MyRole", "MySecondRole"),
                                        List.of("MyType", "VerifiableCredential"),
                                        theFormat == Format.JWT_VC),
                                List.of(getRoleModel("MyRole"), getRoleModel("MySecondRole")),
                                getOidc4VpClient("did:key:2",
                                        Map.of("vctypes_MyType", theFormat.toString()),
                                        List.of("AnotherRole"),
                                        List.of("MyType", "VerifiableCredential"),
                                        theFormat == Format.JWT_VC),
                                List.of(getRoleModel("AnotherRole"))),
                        new ExpectedResult<>(
                                getCredentialSubject(
                                        Map.of("roles",
                                                Set.of(new Role(Set.of("MyRole", "MySecondRole"), "did:key:1"),
                                                        new Role(Set.of("AnotherRole"), "did:key:2")))),
                                "The request should contain roles from both clients")
                ),
                getArguments(
                        getUserModel(null, null, null),
                        Map.of(getOidc4VpClient("did:key:1",
                                        Map.of("vctypes_MyType", theFormat.toString()),
                                        List.of("MyRole", "MySecondRole"),
                                        List.of("MyType", "VerifiableCredential"),
                                        theFormat == Format.JWT_VC),
                                List.of(getRoleModel("MyRole"), getRoleModel("MySecondRole")),
                                getOidc4VpClient("did:key:2",
                                        Map.of("vctypes_AnotherType", theFormat.toString()),
                                        List.of("AnotherRole"),
                                        List.of("AnotherType", "VerifiableCredential"),
                                        theFormat == Format.JWT_VC),
                                List.of(getRoleModel("AnotherRole"))),
                        new ExpectedResult<>(
                                getCredentialSubject(
                                        Map.of("roles",
                                                Set.of(new Role(Set.of("MyRole", "MySecondRole"), "did:key:1")))),
                                "Only roles for supported clients should be included.")
                ),
                getArguments(
                        getUserModel(null, null, null),
                        Map.of(getOidc4VpClient("did:key:1",
                                        Map.of("vctypes_MyType", theFormat.toString()),
                                        List.of("MyRole", "MySecondRole"),
                                        Map.of("more", "claims"),
                                        List.of("MyType", "VerifiableCredential"),
                                        theFormat == Format.JWT_VC),
                                List.of(getRoleModel("MyRole"), getRoleModel("MySecondRole")),
                                getOidc4VpClient("did:key:2",
                                        Map.of("vctypes_MyType", theFormat.toString()),
                                        List.of("AnotherRole"),
                                        Map.of("additional", "claim"),
                                        List.of("MyType", "VerifiableCredential"),
                                        theFormat == Format.JWT_VC),
                                List.of(getRoleModel("AnotherRole"))),
                        new ExpectedResult<>(
                                getCredentialSubject(
                                        Map.of("roles",
                                                Set.of(new Role(Set.of("MyRole", "MySecondRole"), "did:key:1"),
                                                        new Role(Set.of("AnotherRole"), "did:key:2")),
                                                "additional", "claim", "more", "claims")),
                                "Additional claims should be included.")
                ),
                getArguments(
                        getUserModel(null, null, null),
                        Map.of(getOidc4VpClient("did:key:1",
                                        Map.of("vctypes_MyType", theFormat.toString()),
                                        List.of("MyRole", "MySecondRole"),
                                        List.of("MyType", "VerifiableCredential"),
                                        theFormat == Format.JWT_VC),
                                List.of(getRoleModel("MyRole"), getRoleModel("MySecondRole")),
                                getOidc4VpClient("did:key:2",
                                        Map.of("vctypes_MyType", theFormat.toString()),
                                        List.of("AnotherRole"),
                                        Map.of("additional", "claim"),
                                        List.of("MyType", "VerifiableCredential"),
                                        theFormat == Format.JWT_VC),
                                List.of(getRoleModel("AnotherRole"))),
                        new ExpectedResult<>(
                                getCredentialSubject(
                                        Map.of("additional", "claim", "roles",
                                                Set.of(new Role(Set.of("MyRole", "MySecondRole"), "did:key:1"),
                                                        new Role(Set.of("AnotherRole"), "did:key:2")))),
                                "Additional claims should be included.")
                )
        );
    }

    private static Stream<Arguments> provideUserAndClientsLDP() {
        return Stream.of(
                getArguments(getUserModel("e@mail.org", "Happy", "User"),
                        Map.of(getOidc4VpClient("did:key:1",
                                        Map.of("vctypes_MyType", Format.LDP_VC.toString()),
                                        List.of("MyRole"),
                                        List.of("MyType", "VerifiableCredential"),
                                        true),
                                List.of(getRoleModel("MyRole"))),
                        new ExpectedResult<>(
                                getCredentialSubject(
                                        Map.of("email", "e@mail.org", "familyName", "User", "firstName", "Happy", "roles",
                                                Set.of(new Role(Set.of("MyRole"), "did:key:1")))),
                                "A valid Credential should have been returned.")
                ),
                getArguments(getUserModel("e@mail.org", null, "User"),
                        Map.of(getOidc4VpClient("did:key:1",
                                        Map.of("vctypes_MyType", Format.LDP_VC.toString()),
                                        List.of("MyRole"),
                                        List.of("MyType", "VerifiableCredential"),
                                        true),
                                List.of(getRoleModel("MyRole"))),
                        new ExpectedResult<>(
                                getCredentialSubject(
                                        Map.of("email", "e@mail.org", "familyName", "User", "roles",
                                                Set.of(new Role(Set.of("MyRole"), "did:key:1")))),
                                "A valid Credential should have been returned.")
                ),
                getArguments(
                        getUserModel("e@mail.org", null, null),
                        Map.of(getOidc4VpClient("did:key:1",
                                        Map.of("vctypes_MyType", Format.LDP_VC.toString()),
                                        List.of("MyRole"),
                                        List.of("MyType", "VerifiableCredential"),
                                        true),
                                List.of(getRoleModel("MyRole"))),
                        new ExpectedResult<>(
                                getCredentialSubject(
                                        Map.of("email", "e@mail.org", "roles",
                                                Set.of(new Role(Set.of("MyRole"), "did:key:1")))),
                                "A valid Credential should have been returned.")
                ),
                getArguments(
                        getUserModel(null, null, null),
                        Map.of(getOidc4VpClient("did:key:1",
                                        Map.of("vctypes_MyType", Format.LDP_VC.toString()),
                                        List.of("MyRole"),
                                        List.of("MyType", "VerifiableCredential"),
                                        true),
                                List.of(getRoleModel("MyRole"))),
                        new ExpectedResult<>(
                                getCredentialSubject(
                                        Map.of("roles",
                                                Set.of(new Role(Set.of("MyRole"), "did:key:1")))),
                                "A valid Credential should have been returned.")
                ),
                getArguments(
                        getUserModel(null, null, null),
                        Map.of(getOidc4VpClient("did:key:1",
                                        Map.of("vctypes_MyType", Format.LDP_VC.toString()),
                                        List.of("MyRole", "MySecondRole"),
                                        List.of("MyType", "VerifiableCredential"),
                                        true),
                                List.of(getRoleModel("MyRole"), getRoleModel("MySecondRole"))),
                        new ExpectedResult<>(
                                getCredentialSubject(
                                        Map.of("roles",
                                                Set.of(new Role(Set.of("MyRole", "MySecondRole"), "did:key:1")))),
                                "Multiple roles should be included")
                ),
                getArguments(
                        getUserModel(null, null, null),
                        Map.of(getOidc4VpClient("did:key:1",
                                        Map.of("vctypes_MyType", Format.LDP_VC.toString()),
                                        List.of("MyRole", "MySecondRole"),
                                        List.of("MyType", "VerifiableCredential"),
                                        true),
                                List.of(getRoleModel("MyRole"))),
                        new ExpectedResult<>(
                                getCredentialSubject(
                                        Map.of("roles",
                                                Set.of(new Role(Set.of("MyRole"), "did:key:1")))),
                                "Only assigned roles should be included.")
                ),
                getArguments(
                        getUserModel(null, null, null),
                        Map.of(getOidc4VpClient("did:key:1",
                                        Map.of("vctypes_MyType", Format.LDP_VC.toString()),
                                        List.of("MyRole", "MySecondRole"),
                                        List.of("MyType", "VerifiableCredential"),
                                        true),
                                List.of(getRoleModel("MyRole"), getRoleModel("MySecondRole")),
                                getOidc4VpClient("did:key:2",
                                        Map.of("vctypes_MyType", Format.LDP_VC.toString()),
                                        List.of("AnotherRole"),
                                        List.of("MyType", "VerifiableCredential"),
                                        true),
                                List.of(getRoleModel("AnotherRole"))),
                        new ExpectedResult<>(
                                getCredentialSubject(
                                        Map.of("roles",
                                                Set.of(new Role(Set.of("MyRole", "MySecondRole"), "did:key:1"),
                                                        new Role(Set.of("AnotherRole"), "did:key:2")))),
                                "The request should contain roles from both clients")
                ),
                getArguments(
                        getUserModel(null, null, null),
                        Map.of(getOidc4VpClient("did:key:1",
                                        Map.of("vctypes_MyType", Format.LDP_VC.toString()),
                                        List.of("MyRole", "MySecondRole"),
                                        List.of("MyType", "VerifiableCredential"),
                                        true),
                                List.of(getRoleModel("MyRole"), getRoleModel("MySecondRole")),
                                getOidc4VpClient("did:key:2",
                                        Map.of("vctypes_AnotherType", Format.LDP_VC.toString()),
                                        List.of("AnotherRole"),
                                        List.of("MyType", "VerifiableCredential"),
                                        true),
                                List.of(getRoleModel("AnotherRole"))),
                        new ExpectedResult<>(
                                getCredentialSubject(
                                        Map.of("roles",
                                                Set.of(new Role(Set.of("MyRole", "MySecondRole"), "did:key:1")))),
                                "Only roles for supported clients should be included.")
                ),
                getArguments(
                        getUserModel(null, null, null),
                        Map.of(getOidc4VpClient("did:key:1",
                                        Map.of("vctypes_MyType", Format.LDP_VC.toString()),
                                        List.of("MyRole", "MySecondRole"),
                                        Map.of("more", "claims"),
                                        List.of("MyType", "VerifiableCredential"),
                                        true),
                                List.of(getRoleModel("MyRole"), getRoleModel("MySecondRole")),
                                getOidc4VpClient("did:key:2",
                                        Map.of("vctypes_MyType", Format.LDP_VC.toString()),
                                        List.of("AnotherRole"),
                                        Map.of("additional", "claim"),
                                        List.of("MyType", "VerifiableCredential"),
                                        true),
                                List.of(getRoleModel("AnotherRole"))),
                        new ExpectedResult<>(
                                getCredentialSubject(
                                        Map.of("roles",
                                                Set.of(new Role(Set.of("MyRole", "MySecondRole"), "did:key:1"),
                                                        new Role(Set.of("AnotherRole"), "did:key:2")),
                                                "additional", "claim", "more", "claims")),
                                "Additional claims should be included.")
                ),
                getArguments(
                        getUserModel(null, null, null),
                        Map.of(getOidc4VpClient("did:key:1",
                                        Map.of("vctypes_MyType", Format.LDP_VC.toString()),
                                        List.of("MyRole", "MySecondRole"),
                                        List.of("MyType", "VerifiableCredential"),
                                        true),
                                List.of(getRoleModel("MyRole"), getRoleModel("MySecondRole")),
                                getOidc4VpClient("did:key:2",
                                        Map.of("vctypes_MyType", Format.LDP_VC.toString()),
                                        List.of("AnotherRole"),
                                        Map.of("additional", "claim"),
                                        List.of("MyType", "VerifiableCredential"),
                                        true),
                                List.of(getRoleModel("AnotherRole"))),
                        new ExpectedResult<>(
                                getCredentialSubject(
                                        Map.of("additional", "claim", "roles",
                                                Set.of(new Role(Set.of("MyRole", "MySecondRole"), "did:key:1"),
                                                        new Role(Set.of("AnotherRole"), "did:key:2")))),
                                "Additional claims should be included.")
                )
        );
    }

    private static Stream<Arguments> provideTypesAndClients() {
        return Stream.of(
                Arguments.of(Stream.of(getOidcClient(), getNullClient(), getOidc4VpClient(
                                Map.of("vctypes_TestType", Format.LDP_VC.toString()),
                                List.of("TestType", "VerifiableCredential"),
                                true)),
                        new ExpectedResult<>(Set.of(getCredential("TestType", Format.LDP_VC)),
                                "The list of configured types should be returned.")),
                Arguments.of(Stream.of(getOidcClient(), getNullClient()),
                        new ExpectedResult<>(Set.of(), "An empty list should be returned if nothing is configured.")),
                Arguments.of(Stream.of(),
                        new ExpectedResult<>(Set.of(), "An empty list should be returned if nothing is configured.")),
                Arguments.of(
                        Stream.of(getOidc4VpClient(Map.of("vctypes_TestType", Format.LDP_VC.toString(),
                                        "another", "attribute"),
                                List.of("MyType", "VerifiableCredential"),
                                true)),
                        new ExpectedResult<>(Set.of(getCredential("TestType", Format.LDP_VC)),
                                "The list of configured types should be returned.")),
                Arguments.of(Stream.of(getOidc4VpClient(
                                Map.of("vctypes_TestTypeA", Format.LDP_VC.toString(), "vctypes_TestTypeB",
                                        Format.LDP_VC.toString()),
                                List.of("MyType", "VerifiableCredential"),
                                true)),
                        new ExpectedResult<>(
                                Set.of(getCredential("TestTypeA", Format.LDP_VC),
                                        getCredential("TestTypeB", Format.LDP_VC)),
                                "The list of configured types should be returned.")),
                Arguments.of(Stream.of(
                                getOidc4VpClient(Map.of(), null, true),
                                getOidc4VpClient(
                                        Map.of("vctypes_TestTypeA", Format.LDP_VC.toString(), "vctypes_TestTypeB",
                                                Format.LDP_VC.toString()),
                                        List.of("TestTypeA", "TestTypeB", "VerifiableCredential"),
                                        true)),
                        new ExpectedResult<>(
                                Set.of(getCredential("TestTypeA", Format.LDP_VC),
                                        getCredential("TestTypeB", Format.LDP_VC)),
                                "The list of configured types should be returned.")),
                Arguments.of(Stream.of(
                                getOidc4VpClient(null, null, true),
                                getOidc4VpClient(
                                        Map.of("vctypes_TestTypeA", Format.LDP_VC.toString(), "vctypes_TestTypeB",
                                                Format.LDP_VC.toString()),
                                        List.of("TestTypeA", "TestTypeB", "VerifiableCredential"),
                                        true)),
                        new ExpectedResult<>(
                                Set.of(getCredential("TestTypeA", Format.LDP_VC),
                                        getCredential("TestTypeB", Format.LDP_VC)),
                                "The list of configured types should be returned.")),
                Arguments.of(Stream.of(
                                getOidc4VpClient(Map.of("vctypes_AnotherType", Format.LDP_VC.toString()),
                                        List.of("TestTypeA", "TestTypeB", "AnotherType"),
                                        true),
                                getOidc4VpClient(
                                        Map.of("vctypes_TestTypeA", Format.LDP_VC.toString(), "vctypes_TestTypeB",
                                                Format.LDP_VC.toString()),
                                        List.of("TestTypeA", "TestTypeB", "VerifiableCredential"),
                                        true)),
                        new ExpectedResult<>(
                                Set.of(getCredential("TestTypeA", Format.LDP_VC),
                                        getCredential("TestTypeB", Format.LDP_VC),
                                        getCredential("AnotherType", Format.LDP_VC)),
                                "The list of configured types should be returned.")),
                Arguments.of(Stream.of(
                                getOidc4VpClient(
                                        Map.of("vctypes_AnotherType", Format.LDP_VC.toString(), "vctypes_AndAnother",
                                                Format.LDP_VC.toString()),
                                        List.of("AnotherType", "AndAnother", "VerfiableCredential"),
                                        true),
                                getOidc4VpClient(
                                        Map.of("vctypes_TestTypeA", Format.LDP_VC.toString(), "vctypes_TestTypeB",
                                                Format.LDP_VC.toString()), List.of("AnotherType", "AndAnother", "VerfiableCredential"),
                                        true)
                        ),
                        new ExpectedResult<>(
                                Set.of(getCredential("TestTypeA", Format.LDP_VC),
                                        getCredential("TestTypeB", Format.LDP_VC),
                                        getCredential("AnotherType", Format.LDP_VC),
                                        getCredential("AndAnother", Format.LDP_VC)),
                                "The list of configured types should be returned."))
        );
    }

    public static SupportedCredential getCredential(String type, Format format) {
        var cred = new SupportedCredential();
        cred.setTypes(List.of(type));
        cred.setFormat(format);
        return cred;
    }

    private static UserModel getUserModel(String email, String firstName, String lastName) {
        UserModel userModel = mock(UserModel.class);
        when(userModel.getEmail()).thenReturn(email);
        when(userModel.getFirstName()).thenReturn(firstName);
        when(userModel.getLastName()).thenReturn(lastName);
        // use answer to allow multiple invocations
        when(userModel.getAttributeStream(eq("firstName"))).then(f -> Stream.of(firstName));
        when(userModel.getAttributeStream(eq("familyName"))).then(f -> Stream.of(lastName));
        when(userModel.getAttributeStream(eq("email"))).then(f -> Stream.of(email));
        return userModel;
    }

    private static RoleModel getRoleModel(String name) {
        RoleModel roleModel = mock(RoleModel.class);
        when(roleModel.getName()).thenReturn(name);
        return roleModel;
    }

    private static ClientModel getOidcClient() {
        ClientModel clientA = mock(ClientModel.class);
        when(clientA.getProtocol()).thenReturn("OIDC");
        return clientA;
    }

    private static ClientModel getNullClient() {
        ClientModel clientA = mock(ClientModel.class);
        when(clientA.getProtocol()).thenReturn(null);
        return clientA;
    }

    private static ClientModel getOidc4VpClient(String clientId, Map<String, String> attributes, List<String> roles,
                                                Map<String, String> additionalClaims, List<String> types, boolean enableTypeMapper) {
        Stream<RoleModel> roleModelStream = roles.stream().map(role -> {
            RoleModel roleModel = mock(RoleModel.class);
            when(roleModel.getName()).thenReturn(role);
            return roleModel;
        });
        List<ProtocolMapperModel> mapperModels = new ArrayList<>();
        ProtocolMapperModel idMapperModel = mock(ProtocolMapperModel.class);
        when(idMapperModel.getProtocolMapper()).thenReturn(OID4VPSubjectIdMapper.MAPPER_ID);
        when(idMapperModel.getProtocol()).thenReturn(OID4VPClientRegistrationProviderFactory.PROTOCOL_ID);
        when(idMapperModel.getConfig()).thenReturn(Map.of(OID4VPSubjectIdMapper.ID_KEY, "urn:uuid:dummy-id"));
        mapperModels.add(idMapperModel);

        if (clientId != null) {
            ProtocolMapperModel roleMapperModel = mock(ProtocolMapperModel.class);
            when(roleMapperModel.getProtocol()).thenReturn(OID4VPClientRegistrationProviderFactory.PROTOCOL_ID);
            when(roleMapperModel.getProtocolMapper()).thenReturn(OID4VPTargetRoleMapper.MAPPER_ID);
            when(roleMapperModel.getConfig()).thenReturn(
                    Map.of(OID4VPTargetRoleMapper.SUBJECT_PROPERTY_CONFIG_KEY, "roles",
                            OID4VPTargetRoleMapper.CLIENT_CONFIG_KEY, clientId));
            mapperModels.add(roleMapperModel);
        }

        if (types != null && enableTypeMapper) {
            types.forEach(t -> {
                ProtocolMapperModel typeMapper = mock(ProtocolMapperModel.class);
                when(typeMapper.getProtocolMapper()).thenReturn(OID4VPTypeMapper.MAPPER_ID);
                when(typeMapper.getProtocol()).thenReturn(OID4VPClientRegistrationProviderFactory.PROTOCOL_ID);
                when(typeMapper.getConfig()).thenReturn(
                        Map.of(OID4VPTypeMapper.TYPE_KEY, t));
                mapperModels.add(typeMapper);
            });
        }
        ProtocolMapperModel familyNameMapper = mock(ProtocolMapperModel.class);
        when(familyNameMapper.getProtocolMapper()).thenReturn(OID4VPUserAttributeMapper.MAPPER_ID);
        when(familyNameMapper.getProtocol()).thenReturn(OID4VPClientRegistrationProviderFactory.PROTOCOL_ID);
        when(familyNameMapper.getConfig()).thenReturn(
                Map.of(OID4VPUserAttributeMapper.USER_ATTRIBUTE_KEY, "familyName",
                        OID4VPUserAttributeMapper.SUBJECT_PROPERTY_CONFIG_KEY, "familyName",
                        OID4VPUserAttributeMapper.AGGREGATE_ATTRIBUTES_KEY, "false"));
        mapperModels.add(familyNameMapper);

        ProtocolMapperModel firstNameMapper = mock(ProtocolMapperModel.class);
        when(firstNameMapper.getProtocolMapper()).thenReturn(OID4VPUserAttributeMapper.MAPPER_ID);
        when(firstNameMapper.getProtocol()).thenReturn(OID4VPClientRegistrationProviderFactory.PROTOCOL_ID);
        when(firstNameMapper.getConfig()).thenReturn(Map.of(OID4VPUserAttributeMapper.USER_ATTRIBUTE_KEY, "firstName",
                OID4VPUserAttributeMapper.SUBJECT_PROPERTY_CONFIG_KEY, "firstName",
                OID4VPUserAttributeMapper.AGGREGATE_ATTRIBUTES_KEY, "false"));
        mapperModels.add(firstNameMapper);

        ProtocolMapperModel emailMapper = mock(ProtocolMapperModel.class);
        when(emailMapper.getProtocolMapper()).thenReturn(OID4VPUserAttributeMapper.MAPPER_ID);
        when(emailMapper.getProtocol()).thenReturn(OID4VPClientRegistrationProviderFactory.PROTOCOL_ID);
        when(emailMapper.getConfig()).thenReturn(Map.of(OID4VPUserAttributeMapper.USER_ATTRIBUTE_KEY, "email",
                OID4VPUserAttributeMapper.SUBJECT_PROPERTY_CONFIG_KEY, "email",
                OID4VPUserAttributeMapper.AGGREGATE_ATTRIBUTES_KEY, "false"));
        mapperModels.add(emailMapper);

        additionalClaims.entrySet().forEach(entry -> {
            ProtocolMapperModel claimMapper = mock(ProtocolMapperModel.class);
            when(claimMapper.getProtocolMapper()).thenReturn(OID4VPStaticClaimMapper.MAPPER_ID);
            when(claimMapper.getProtocol()).thenReturn(OID4VPClientRegistrationProviderFactory.PROTOCOL_ID);
            when(claimMapper.getConfig()).thenReturn(Map.of(OID4VPStaticClaimMapper.STATIC_CLAIM_KEY, entry.getValue(),
                    OID4VPStaticClaimMapper.SUBJECT_PROPERTY_CONFIG_KEY, entry.getKey()));
            mapperModels.add(claimMapper);
        });

        ClientModel clientA = mock(ClientModel.class);
        when(clientA.getProtocol()).thenReturn(OID4VPClientRegistrationProviderFactory.PROTOCOL_ID);
        when(clientA.getClientId()).thenReturn(clientId);
        when(clientA.getAttributes()).thenReturn(attributes);
        when(clientA.getProtocolMappersStream()).thenReturn(mapperModels.stream());
        when(clientA.getRolesStream()).thenReturn(roleModelStream);
        return clientA;
    }

    private static ClientModel getOidc4VpClient(String clientId, Map<String, String> attributes, List<String> roles, List<String> types, boolean enableTypeMapper) {
        return getOidc4VpClient(clientId, attributes, roles, Map.of(), types, enableTypeMapper);
    }

    private static ClientModel getOidc4VpClient(Map<String, String> attributes, List<String> types, boolean enableTypeMapper) {
        return getOidc4VpClient(null, attributes, List.of(), types, enableTypeMapper);
    }
}