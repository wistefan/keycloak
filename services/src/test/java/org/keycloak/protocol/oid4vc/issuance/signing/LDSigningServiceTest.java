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
import org.keycloak.crypto.KeyUse;
import org.keycloak.crypto.KeyWrapper;
import org.keycloak.models.KeyManager;
import org.keycloak.models.KeycloakContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.protocol.oid4vc.issuance.signing.vcdm.Ed255192018Suite;
import org.keycloak.protocol.oid4vc.issuance.signing.vcdm.SecuritySuite;
import org.keycloak.protocol.oid4vc.model.VerifiableCredential;

import java.io.IOException;
import java.io.StringWriter;
import java.security.Key;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneId;

import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Matchers.any;
import static org.mockito.Matchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class LDSigningServiceTest extends SigningServiceTest {
    private ObjectMapper objectMapper = new ObjectMapper();


    @Test
    public void testEd25519Signature() throws IOException {
        KeyWrapper keyWrapper = getEd25519Key("ec-key");


        LDSigningService ldSigningService = new LDSigningService(
                getMockSession(keyWrapper),
                "did:key:",
                Clock.fixed(Instant.ofEpochSecond(1000), ZoneId.of("UTC")),
                Ed255192018Suite.PROOF_TYPE,
                objectMapper);


        var testCredential = getTestCredential();
        VerifiableCredential signedCredential = ldSigningService.signCredential(testCredential);

        verify(testCredential, signedCredential.getProof().getProofValue(), keyWrapper.getPublicKey());
    }

    private void verify(VerifiableCredential testCredential, String proof, Key publicKey) throws IOException {
        Ed25519Signer signer = new Ed25519Signer();
//        signer.init(false, (PublicKey) publicKey);
//        SecuritySuite securitySuite = new Ed255192018Suite(objectMapper);
//        testCredential.setProof(null);
//        byte[] transformedData = securitySuite.transform(testCredential);
//        byte[] hashedData = securitySuite.digest(transformedData);
//        signer.update(hashedData, 0, hashedData.length);

//        assertTrue(signer.verifySignature(Base64.decode(proof, Base64.URL_SAFE)), "The signature should be valid");

    }


}