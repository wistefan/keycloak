package org.keycloak.protocol.oid4vc.issuance.signing;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.bouncycastle.crypto.generators.Ed25519KeyPairGenerator;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.Ed25519KeyGenerationParameters;
import org.bouncycastle.crypto.signers.Ed25519Signer;
import org.bouncycastle.crypto.util.PrivateKeyInfoFactory;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.junit.jupiter.api.Test;
import org.keycloak.common.util.Base64;
import org.keycloak.protocol.oid4vc.model.VerifiableCredential;
import org.keycloak.protocol.oid4vc.signing.KeyLoader;
import org.keycloak.protocol.oid4vc.signing.LDSigningService;
import org.keycloak.protocol.oid4vc.signing.vcdm.Ed255192018Suite;
import org.keycloak.protocol.oid4vc.signing.vcdm.SecuritySuite;

import java.io.IOException;
import java.io.StringWriter;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneId;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertTrue;

class LDSigningServiceTest extends SigningServiceTest {
    private ObjectMapper objectMapper = new ObjectMapper();



    @Test
    public void testEd25519Signature() throws IOException {
        Ed25519TestKeyLoader testKeyLoader = new Ed25519TestKeyLoader();
        LDSigningService ldSigningService = new LDSigningService(
                testKeyLoader,
                Optional.of("my-key-id"),
                Clock.fixed(Instant.ofEpochSecond(1000), ZoneId.of("UTC")),
                Ed255192018Suite.PROOF_TYPE,
                objectMapper);


        var testCredential = getTestCredential();
        VerifiableCredential signedCredential = ldSigningService.signCredential(testCredential);

        verify(testCredential, signedCredential.getProof().getProofValue(), testKeyLoader.getPublicKey());
    }

    private void verify(VerifiableCredential testCredential, String proof, AsymmetricKeyParameter publicKey) throws IOException {
        Ed25519Signer signer = new Ed25519Signer();
        signer.init(false, publicKey);
        SecuritySuite securitySuite = new Ed255192018Suite(objectMapper);
        testCredential.setProof(null);
        byte[] transformedData = securitySuite.transform(testCredential);
        byte[] hashedData = securitySuite.digest(transformedData);
        signer.update(hashedData, 0, hashedData.length);

        assertTrue(signer.verifySignature(Base64.decode(proof, Base64.URL_SAFE)), "The signature should be valid");
    }

    class Ed25519TestKeyLoader implements KeyLoader {
        private AsymmetricKeyParameter publicKey;
        private AsymmetricKeyParameter privateKey;

        public Ed25519TestKeyLoader() {
            Ed25519KeyGenerationParameters keygenParams = new Ed25519KeyGenerationParameters(new SecureRandom());

            Ed25519KeyPairGenerator generator = new Ed25519KeyPairGenerator();
            generator.init(keygenParams);
            var keyPair = generator.generateKeyPair();

            publicKey = keyPair.getPublic();
            privateKey = keyPair.getPrivate();
        }

        public AsymmetricKeyParameter getPublicKey() {
            return publicKey;
        }

        public AsymmetricKeyParameter getPrivateKey() {
            return privateKey;
        }

        @Override
        public String loadKey() {
            try {
                var keyInfo = PrivateKeyInfoFactory.createPrivateKeyInfo(getPrivateKey());
                StringWriter stringWriter = new StringWriter();
                JcaPEMWriter pemWriter = new JcaPEMWriter(stringWriter);
                pemWriter.writeObject(keyInfo);
                pemWriter.flush();
                pemWriter.close();
                return stringWriter.toString();

            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        }
    }

}