package org.keycloak.protocol.oid4vc.issuance.signing;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.keycloak.crypto.KeyUse;
import org.keycloak.crypto.KeyWrapper;
import org.keycloak.models.KeyManager;
import org.keycloak.models.KeycloakContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.protocol.oid4vc.model.CredentialSubject;
import org.keycloak.protocol.oid4vc.model.VerifiableCredential;

import java.io.IOException;
import java.io.StringWriter;
import java.net.URI;
import java.security.*;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.UUID;

import static org.mockito.Matchers.*;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

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


    public static KeyWrapper getECKey(String keyId) {
        try {
            Security.addProvider(new BouncyCastleProvider());
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC", "BC");
            kpg.initialize(256);
            var keyPair = kpg.generateKeyPair();
            KeyWrapper kw = new KeyWrapper();
            kw.setPrivateKey(keyPair.getPrivate());
            kw.setPublicKey(keyPair.getPublic());
            kw.setUse(KeyUse.SIG);
            kw.setKid(keyId);
            kw.setType("EC");
            return kw;

        } catch (NoSuchAlgorithmException | NoSuchProviderException e) {
            throw new RuntimeException(e);
        }
    }

    public static KeyWrapper getEd25519Key(String keyId) {
        try {
            Security.addProvider(new BouncyCastleProvider());
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("Ed25519", "BC");
            var keyPair = kpg.generateKeyPair();
            KeyWrapper kw = new KeyWrapper();
            kw.setPrivateKey(keyPair.getPrivate());
            kw.setPublicKey(keyPair.getPublic());
            kw.setUse(KeyUse.SIG);
            kw.setKid(keyId);
            kw.setType("Ed25519");
            return kw;

        } catch (NoSuchAlgorithmException | NoSuchProviderException e) {
            throw new RuntimeException(e);
        }
    }


    public static KeyWrapper getRsaKey(String keyId) {
        try {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
            kpg.initialize(2048);
            var keyPair = kpg.generateKeyPair();
            KeyWrapper kw = new KeyWrapper();
            kw.setPrivateKey(keyPair.getPrivate());
            kw.setPublicKey(keyPair.getPublic());
            kw.setUse(KeyUse.SIG);
            kw.setType("RSA");
            kw.setKid(keyId);
            return kw;
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    public static KeycloakSession getMockSession(KeyWrapper keyWrapper) {

        KeycloakSession session = mock(KeycloakSession.class);
        KeycloakContext context = mock(KeycloakContext.class);
        KeyManager keyManager = mock(KeyManager.class);
        RealmModel realmModel = mock(RealmModel.class);
        when(session.keys()).thenReturn(keyManager);
        when(session.getContext()).thenReturn(context);
        when(context.getRealm()).thenReturn(realmModel);
        when(keyManager.getKey(any(), eq(keyWrapper.getKid()), any(), anyString())).thenReturn(keyWrapper);
        return session;
    }

}
