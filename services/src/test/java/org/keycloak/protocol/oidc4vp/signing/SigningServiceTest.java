package org.keycloak.protocol.oidc4vp.signing;

import org.keycloak.protocol.oidc4vp.model.CredentialSubject;
import org.keycloak.protocol.oidc4vp.model.VerifiableCredential;

import java.net.URI;
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
        VerifiableCredential testCredential = new VerifiableCredential();
        testCredential.setContext(List.of(CONTEXT_URL));
        testCredential.setType(List.of("VerifiableCredential"));
        testCredential.setIssuer(URI.create("did:web:test.org"));
        testCredential.setExpirationDate(Date.from(Instant.ofEpochSecond(2000)));
        testCredential.setIssuanceDate(Date.from(Instant.ofEpochSecond(1000)));
        testCredential.setCredentialSubject(credentialSubject);
        return testCredential;
    }
}
