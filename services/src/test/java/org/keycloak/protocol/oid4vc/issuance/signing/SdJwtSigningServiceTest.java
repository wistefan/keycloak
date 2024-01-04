package org.keycloak.protocol.oid4vc.issuance.signing;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.keycloak.TokenVerifier;
import org.keycloak.common.VerificationException;
import org.keycloak.common.crypto.CryptoIntegration;
import org.keycloak.crypto.Algorithm;
import org.keycloak.models.KeycloakSession;
import org.keycloak.representations.JsonWebToken;

import java.io.IOException;
import java.security.PublicKey;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneId;
import java.util.StringJoiner;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.fail;

class SdJwtSigningServiceTest extends SigningServiceTest {

    @ParameterizedTest
    @MethodSource("provideKeyConfig")
    public void test(KeycloakSession session, String signatureType, PublicKey publicKey) throws IOException {
        CryptoIntegration.init(this.getClass().getClassLoader());

        SdJwtSigningService sdJwtSigningService = new SdJwtSigningService(
                session,
                "my-key-id",
                Clock.fixed(Instant.ofEpochSecond(1000), ZoneId.of("UTC")),
                signatureType,
                new ObjectMapper(),
                3,
                "did:web:test.org");
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
        if (Algorithm.ES256.equals(signatureType)) {
            //  tokenVerifier.verifierContext(new EcVerficationContext(keyLoader.getKeyPair().getPublic()));
        }
        tokenVerifier.publicKey(publicKey);
        try {
            tokenVerifier.verify();
        } catch (VerificationException e) {
            fail("The credential should successfully be verified.", e);
        }
    }

    public static Stream<Arguments> provideKeyConfig() {
        var rsaKey = getRsaKey("my-key-id");
        var ecKey = getECKey("my-key-Id");

        return Stream.of(
                Arguments.of(getMockSession(rsaKey), Algorithm.RS256, rsaKey.getPublicKey())
         //       Arguments.of(getMockSession(ecKey), Algorithm.ES256, ecKey.getPublicKey())
        );
    }
}