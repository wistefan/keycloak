package org.keycloak.protocol.oidc4vp.signing;

import org.bouncycastle.crypto.util.PrivateKeyInfoFactory;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.BeforeAll;
import org.keycloak.TokenVerifier;
import org.keycloak.common.VerificationException;
import org.keycloak.crypto.Algorithm;
import org.keycloak.representations.JsonWebToken;
import org.keycloak.util.TokenUtil;

import java.io.IOException;
import java.io.StringWriter;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneId;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

class JWTSigningServiceTest extends SigningServiceTest {
    private static final String CONTEXT_URL = "https://www.w3.org/2018/credentials/v1";

    @BeforeAll
    public static void setup() {

    }

    @Test
    public void test() {
        RSAKeyLoader keyLoader = new RSAKeyLoader();
        JWTSigningService jwtSigningService = new JWTSigningService(
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


    class RSAKeyLoader implements KeyLoader {

        private KeyPair keyPair;

        public KeyPair getKeyPair() {
            return keyPair;
        }

        public RSAKeyLoader() {
            try {
                KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
                kpg.initialize(2048);
                keyPair = kpg.generateKeyPair();
            } catch (NoSuchAlgorithmException e) {
                throw new RuntimeException(e);
            }
        }

        @Override
        public String loadKey() {

            StringWriter stringWriter = new StringWriter();
            JcaPEMWriter pemWriter = new JcaPEMWriter(stringWriter);
            try {
                pemWriter.writeObject(keyPair);
                pemWriter.flush();
                pemWriter.close();
                return stringWriter.toString();
            } catch (IOException e) {
                throw new RuntimeException(e);
            }

        }
    }
}