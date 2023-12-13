package org.keycloak.protocol.oidc4vp.signing.signatures;

import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.keycloak.protocol.oidc4vp.model.VerifiableCredential;
import org.keycloak.protocol.oidc4vp.signing.SigningServiceException;

import java.io.IOException;
import java.io.StringReader;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.List;

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


