package org.keycloak.testsuite.oid4vc.issuance.signing;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.ws.rs.core.Response;
import org.apache.http.HttpStatus;
import org.jboss.logging.Logger;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.keycloak.common.crypto.CryptoIntegration;
import org.keycloak.common.util.MultivaluedHashMap;
import org.keycloak.crypto.Algorithm;
import org.keycloak.models.KeycloakSession;
import org.keycloak.protocol.oid4vc.issuance.OID4VCIssuerEndpoint;
import org.keycloak.protocol.oid4vc.issuance.TimeProvider;
import org.keycloak.protocol.oid4vc.issuance.signing.JwtSigningService;
import org.keycloak.protocol.oid4vc.model.CredentialOfferURI;
import org.keycloak.protocol.oid4vc.model.Format;
import org.keycloak.representations.idm.ClientRepresentation;
import org.keycloak.representations.idm.RealmRepresentation;
import org.keycloak.services.managers.AppAuthManager;
import org.keycloak.testsuite.util.TokenUtil;

import java.util.List;
import java.util.Map;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

public class OID4VCIssuerEndpointTest extends OID4VCTest {

    private static final Logger LOGGER = Logger.getLogger(JwtSigningServiceTest.class);

    @Rule
    public TokenUtil tokenUtil = new TokenUtil();

    @Before
    public void setup() {
        CryptoIntegration.init(this.getClass().getClassLoader());
    }

    @Test
    public void testGetCredentialOfferURI() throws Exception {
        String token = tokenUtil.getToken();
        testingClient
                .server(TEST_REALM_NAME)
                .run((session) -> {
                    try {
                        testGetCredentialOfferURI(token, session);
                    } catch (Exception e) {
                        throw new RuntimeException(e);
                    }
                });

    }

    public static void testGetCredentialOfferURI(String token, KeycloakSession session) {
        AppAuthManager.BearerTokenAuthenticator authenticator = new AppAuthManager.BearerTokenAuthenticator(session);
        authenticator.setTokenString(token);
        TimeProvider timeProvider = new OID4VCTest.StaticTimeProvider(1000);
        JwtSigningService jwtSigningService = new JwtSigningService(
                session,
                getKeyFromSession(session).getKid(),
                Algorithm.RS256,
                "JWT",
                "did:web:issuer.org",
                timeProvider);
        OID4VCIssuerEndpoint oid4VCIssuerEndpoint = new OID4VCIssuerEndpoint(
                session,
                "did:web:issuer.org",
                Map.of(Format.JWT_VC, jwtSigningService),
                authenticator,
                new ObjectMapper(),
                timeProvider);
        Response response = oid4VCIssuerEndpoint.getCredentialOfferURI("test-credential");

        assertEquals("An offer uri should have been returned.", HttpStatus.SC_OK, response.getStatus());
        CredentialOfferURI credentialOfferURI = new ObjectMapper().convertValue(response.getEntity(), CredentialOfferURI.class);
        assertNotNull("A nonce should be included.", credentialOfferURI.getNonce());
        assertNotNull("The issuer uri should be provided.", credentialOfferURI.getIssuer());

        assertNotNull("", session.getContext().getAuthenticationSession().getUserSessionNotes().get(credentialOfferURI.getNonce()));
    }

    @Override
    public void configureTestRealm(RealmRepresentation testRealm) {
        if (testRealm.getComponents() != null) {
            testRealm.getComponents().add("org.keycloak.keys.KeyProvider", getRsaKeyProvider(RSA_KEY));
            testRealm.getComponents().add("org.keycloak.protocol.oid4vc.issuance.signing.VerifiableCredentialsSigningService", getJwtSigningProvider(RSA_KEY));
        } else {
            testRealm.setComponents(new MultivaluedHashMap<>(
                    Map.of("org.keycloak.keys.KeyProvider", List.of(getRsaKeyProvider(RSA_KEY)),
                            "org.keycloak.protocol.oid4vc.issuance.signing.VerifiableCredentialsSigningService", List.of(getJwtSigningProvider(RSA_KEY))
                    )));
        }
        ClientRepresentation clientRepresentation = getTestClient("did:web:test.org");
        if (testRealm.getClients() != null) {
            testRealm.getClients().add(clientRepresentation);
        } else {
            testRealm.setClients(List.of(clientRepresentation));
        }
        if (testRealm.getRoles() != null) {
            testRealm.getRoles().getClient()
                    .put(clientRepresentation.getClientId(), List.of(getRoleRepresentation("testRole", clientRepresentation.getClientId())));
        } else {
            testRealm.getRoles()
                    .setClient(Map.of(clientRepresentation.getClientId(), List.of(getRoleRepresentation("testRole", clientRepresentation.getClientId()))));
        }
        if (testRealm.getUsers() != null) {
            testRealm.getUsers().add(getUserRepresentation(Map.of(clientRepresentation.getClientId(), List.of("testRole"))));
        } else {
            testRealm.setUsers(List.of(getUserRepresentation(Map.of(clientRepresentation.getClientId(), List.of("testRole")))));
        }
    }

}
