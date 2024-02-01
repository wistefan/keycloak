package org.keycloak.testsuite.oid4vc.issuance.signing;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.ws.rs.BadRequestException;
import jakarta.ws.rs.core.Response;
import org.apache.http.HttpStatus;
import org.jboss.logging.Logger;
import org.junit.Before;
import org.junit.Test;
import org.keycloak.common.crypto.CryptoIntegration;
import org.keycloak.common.util.MultivaluedHashMap;
import org.keycloak.crypto.Algorithm;
import org.keycloak.models.KeycloakSession;
import org.keycloak.protocol.oid4vc.issuance.OID4VCIssuerEndpoint;
import org.keycloak.protocol.oid4vc.issuance.TimeProvider;
import org.keycloak.protocol.oid4vc.issuance.signing.JwtSigningService;
import org.keycloak.protocol.oid4vc.model.Format;
import org.keycloak.representations.idm.RealmRepresentation;
import org.keycloak.services.managers.AppAuthManager;
import org.keycloak.testsuite.runonserver.RunOnServerException;

import java.util.List;
import java.util.Map;

import static org.junit.Assert.assertEquals;

public class OID4VCIssuerEndpointTest extends OID4VCTest {

    private static final Logger LOGGER = Logger.getLogger(JwtSigningServiceTest.class);

    @Before
    public void setup() {
        CryptoIntegration.init(this.getClass().getClassLoader());
    }

    @Test
    public void testGetCredentialOfferURI() {
        try {

            getTestingClient()
                    .server(TEST_REALM_NAME)
                    .run((session) -> testGetCredentialOfferURI(session));
        } catch (Exception e) {
            if (e instanceof RunOnServerException && e.getCause() instanceof BadRequestException) {
                BadRequestException bre = (BadRequestException) e.getCause();
                LOGGER.warnf("Message: %s", bre.getMessage());
                e.printStackTrace();
            }
        }
    }

    public static void testGetCredentialOfferURI(KeycloakSession session) {
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
                new AppAuthManager.BearerTokenAuthenticator(session),
                new ObjectMapper(),
                timeProvider);

        Response response = oid4VCIssuerEndpoint.getCredentialOfferURI("test-credential");

        LOGGER.warnf("The uri %s", response.getEntity());
        assertEquals("An offer uri should have been returned.", HttpStatus.SC_OK, response.getStatus());
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
        if (testRealm.getClients() != null) {
            testRealm.getClients().add(getTestClient("did:web:test.org"));
        } else {
            testRealm.setClients(List.of(getTestClient("did:web:test.org")));
        }
    }

}
