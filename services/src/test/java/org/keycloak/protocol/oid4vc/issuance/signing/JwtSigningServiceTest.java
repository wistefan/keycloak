package org.keycloak.protocol.oid4vc.issuance.signing;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.keycloak.TokenVerifier;
import org.keycloak.common.VerificationException;
import org.keycloak.crypto.Algorithm;
import org.keycloak.representations.JsonWebToken;

import java.security.PublicKey;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneId;

import static org.junit.jupiter.api.Assertions.fail;

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
                Algorithm.RS256,
                "did:web:test.org");

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