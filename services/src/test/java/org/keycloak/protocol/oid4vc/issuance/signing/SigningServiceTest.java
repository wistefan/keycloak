package org.keycloak.protocol.oid4vc.issuance.signing;

import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.keycloak.protocol.oid4vc.model.CredentialSubject;
import org.keycloak.protocol.oid4vc.model.VerifiableCredential;

import java.io.IOException;
import java.io.StringWriter;
import java.net.URI;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.UUID;

public abstract class SigningServiceTest {


    protected static final String CONTEXT_URL = "https://www.w3.org/2018/credentials/v1";

    protected VerifiableCredential getTestCredential() {
        CredentialSubject credentialSubject = new CredentialSubject();
        credentialSubject.setClaims("id", String.format("uri:uuid:%s", UUID.randomUUID()));
        credentialSubject.setClaims("test", "test");
        credentialSubject.setClaims("arrayClaim", List.of("a", "b", "c"));
        VerifiableCredential testCredential = new VerifiableCredential();
        testCredential.setContext(List.of(CONTEXT_URL));
        testCredential.setType(List.of("VerifiableCredential"));
        testCredential.setIssuer(URI.create("did:web:test.org"));
        testCredential.setExpirationDate(Date.from(Instant.ofEpochSecond(2000)));
        testCredential.setIssuanceDate(Date.from(Instant.ofEpochSecond(1000)));
        testCredential.setCredentialSubject(credentialSubject);
        return testCredential;
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
