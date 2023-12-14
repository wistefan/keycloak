package org.keycloak.protocol.oidc4vp.signing.vcdm;

import org.keycloak.protocol.oidc4vp.model.VerifiableCredential;

public interface SecuritySuite {

    byte[] transform(VerifiableCredential verifiableCredential);

    byte[] digest(byte[] transformedData);

    byte[] sign(byte[] hashData, String key);

    String getProofType();

}
