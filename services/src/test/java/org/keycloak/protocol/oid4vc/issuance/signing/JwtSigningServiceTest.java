package org.keycloak.protocol.oid4vc.issuance.signing;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.keycloak.TokenVerifier;
import org.keycloak.common.VerificationException;
import org.keycloak.crypto.Algorithm;
import org.keycloak.representations.JsonWebToken;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneId;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.fail;

class JwtSigningServiceTest extends SigningServiceTest {
    private static final String CONTEXT_URL = "https://www.w3.org/2018/credentials/v1";

    @BeforeAll
    public static void setup() {

    }

    @Test
    public void test() {
        RSAKeyLoader keyLoader = new RSAKeyLoader();
        JwtSigningService jwtSigningService = new JwtSigningService(
                keyLoader,
                Optional.of("my-key-id"),
                Clock.fixed(Instant.ofEpochSecond(1000), ZoneId.of("UTC")),
                Algorithm.RS256);

        var testCredential = getTestCredential();

        String jwtCredential = jwtSigningService.signCredential(testCredential);
        var verifier = TokenVerifier.create(jwtCredential, JsonWebToken.class);
        verifier.publicKey(keyLoader.getKeyPair().getPublic());
        try {
            verifier.verify();
        } catch (VerificationException e) {
            fail("The credential should successfully be verified.", e);
        }
    }



}