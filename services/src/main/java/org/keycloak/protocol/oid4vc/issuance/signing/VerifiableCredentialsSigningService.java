package org.keycloak.protocol.oid4vc.issuance.signing;


import org.keycloak.protocol.oid4vc.model.VerifiableCredential;

/**
 * Interface to be used for signing verifiable credentials.
 *
 * @author <a href="https://github.com/wistefan">Stefan Wiedemann</a>
 */
public interface VerifiableCredentialsSigningService<T> {
    /**
     * Takes a verifiable credential and signs it according to the implementation.
     * Depending on the type of the SigningService, it will return a signed representation of the credential
     *
     * @param verifiableCredential the credential to sign
     * @return a signed representation
     */
    T signCredential(VerifiableCredential verifiableCredential);
}
