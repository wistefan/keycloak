package org.keycloak.protocol.oid4vp.signing;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.keycloak.TokenVerifier;
import org.keycloak.common.VerificationException;
import org.keycloak.crypto.Algorithm;
import org.keycloak.representations.JsonWebToken;

import java.io.IOException;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneId;
import java.util.Optional;
import java.util.StringJoiner;

import static org.junit.jupiter.api.Assertions.fail;

class SdJwtSigningServiceTest extends SigningServiceTest {

    @Test
    public void test() throws IOException {

        RSAKeyLoader keyLoader = new RSAKeyLoader();
        SdJwtSigningService sdJwtSigningService = new SdJwtSigningService(
                keyLoader,
                Optional.of("my-key-id"),
                Clock.fixed(Instant.ofEpochSecond(1000), ZoneId.of("UTC")),
                Algorithm.RS256,
                new ObjectMapper(),
                3);
        String sdJwt = sdJwtSigningService.signCredential(getTestCredential());

        // the sd-jwt is dot-concatenated header.payload.signature.disclosure1.___.disclosureN
        String[] splittedToken = sdJwt.split("\\.");

        String jwt = new StringJoiner(".")
                // header
                .add(splittedToken[0])
                // payload
                .add(splittedToken[1])
                // signature
                .add(splittedToken[2])
                .toString();
        var tokenVerifier = TokenVerifier.create(jwt, JsonWebToken.class);
        tokenVerifier.publicKey(keyLoader.getKeyPair().getPublic());
        try {
            tokenVerifier.verify();
        } catch (VerificationException e) {
            fail("The credential should successfully be verified.", e);
        }
    }
}