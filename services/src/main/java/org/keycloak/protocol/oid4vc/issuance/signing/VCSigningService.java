package org.keycloak.protocol.oid4vc.issuance.signing;


import org.keycloak.protocol.oid4vc.model.VerifiableCredential;

public interface VCSigningService<T> {

    T signCredential(VerifiableCredential verifiableCredential);
}
