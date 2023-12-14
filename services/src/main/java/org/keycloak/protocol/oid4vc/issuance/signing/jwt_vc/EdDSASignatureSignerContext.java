package org.keycloak.protocol.oid4vc.issuance.signing.jwt_vc;

import org.keycloak.crypto.KeyWrapper;
import org.keycloak.crypto.SignatureException;
import org.keycloak.crypto.SignatureSignerContext;

import java.security.PrivateKey;
import java.security.Signature;

public class EdDSASignatureSignerContext implements SignatureSignerContext {

    public static final String ED_25519 = "Ed25519";

    private final KeyWrapper key;

    public EdDSASignatureSignerContext(KeyWrapper key) {
        this.key = key;
    }

    @Override
    public String getKid() {
        return key.getKid();
    }

    @Override
    public String getAlgorithm() {
        return key.getAlgorithm();
    }

    @Override
    public String getHashAlgorithm() {
        return key.getAlgorithm();
    }

    @Override
    public byte[] sign(byte[] data) throws SignatureException {
        try {
            Signature signature = Signature.getInstance(key.getAlgorithm());
            signature.initSign((PrivateKey) key.getPrivateKey());
            signature.update(data);
            return signature.sign();
        } catch (Exception e) {
            throw new SignatureException("Signing failed", e);
        }
    }
}
