package org.keycloak.protocol.oid4vc.issuance.signing.vcdm;

import org.keycloak.protocol.oid4vc.model.VerifiableCredential;

import java.security.PrivateKey;

/**
 * Interface for all implementations of LD-Signature Suites
 * <p>
 * {@see https://w3c-ccg.github.io/ld-cryptosuite-registry/}
 *
 * @author <a href="https://github.com/wistefan">Stefan Wiedemann</a>
 */
public interface SecuritySuite {

    byte[] transform(VerifiableCredential verifiableCredential);

    byte[] digest(byte[] transformedData);

    byte[] sign(byte[] hashData, PrivateKey key);

    String getProofType();

}
