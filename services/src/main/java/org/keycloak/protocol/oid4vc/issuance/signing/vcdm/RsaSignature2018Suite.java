package org.keycloak.protocol.oid4vc.issuance.signing.vcdm;

import org.keycloak.protocol.oid4vc.model.VerifiableCredential;

public class RsaSignature2018Suite implements SecuritySuite {

    private static final String CANONICALIZATION_ALGORITHM = "https://w3id.org/security#GCA2015";
    private static final String DIGEST_ALGORITHM = "https://www.ietf.org/assignments/jwa-parameters#SHA256";
    private static final String SIGNATURE_ALGORITHM = "https://www.ietf.org/assignments/jwa-parameters#RS256";

    public static final String PROOF_TYPE = "RsaSignature2018";

    @Override
    public byte[] transform(VerifiableCredential verifiableCredential) {
        return new byte[0];
    }

    @Override
    public byte[] digest(byte[] transformedData) {
        return new byte[0];
    }

    @Override
    public byte[] sign(byte[] hashData, String key) {
        return new byte[0];
    }

    @Override
    public String getProofType() {
        return PROOF_TYPE;
    }
}


