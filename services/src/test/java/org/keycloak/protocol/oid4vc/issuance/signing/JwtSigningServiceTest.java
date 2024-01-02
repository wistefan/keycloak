package org.keycloak.protocol.oid4vc.issuance.signing;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.JWK;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.keycloak.TokenVerifier;
import org.keycloak.common.VerificationException;
import org.keycloak.crypto.Algorithm;
import org.keycloak.crypto.KeyWrapper;
import org.keycloak.models.KeyManager;
import org.keycloak.models.KeycloakContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.representations.JsonWebToken;

import java.security.PublicKey;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneId;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.fail;
import static org.mockito.Matchers.any;
import static org.mockito.Matchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class JwtSigningServiceTest extends SigningServiceTest {
    @BeforeAll
    public static void setup() {

    }

    @Test
    public void test() {
        var keyWrapper = getRsaKey("my-key-id");

        JwtSigningService jwtSigningService = new JwtSigningService(
                getMockSession(keyWrapper),
                "my-key-id",
                Clock.fixed(Instant.ofEpochSecond(1000), ZoneId.of("UTC")),
                Algorithm.RS256);

        var testCredential = getTestCredential();

        String jwtCredential = jwtSigningService.signCredential(testCredential);
        var verifier = TokenVerifier.create(jwtCredential, JsonWebToken.class);
        verifier.publicKey((PublicKey) keyWrapper.getPublicKey());
        try {
            verifier.verify();
        } catch (VerificationException e) {
            fail("The credential should successfully be verified.", e);
        }
    }



}