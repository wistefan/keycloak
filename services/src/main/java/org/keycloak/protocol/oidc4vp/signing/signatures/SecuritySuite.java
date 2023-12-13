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

public interface SecuritySuite {

    byte[] transform(VerifiableCredential verifiableCredential);

    byte[] digest(byte[] transformedData);

    byte[] sign(byte[] hashData, String key);

    String getProofType();

}
