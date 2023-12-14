package org.keycloak.protocol.oid4vc.signing.vcdm;

import org.keycloak.protocol.oid4vc.model.VerifiableCredential;

public interface SecuritySuite {

    byte[] transform(VerifiableCredential verifiableCredential);

    byte[] digest(byte[] transformedData);

    byte[] sign(byte[] hashData, String key);

    String getProofType();

}
