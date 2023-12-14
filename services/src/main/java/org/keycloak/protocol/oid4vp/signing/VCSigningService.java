package org.keycloak.protocol.oid4vp.signing;


import org.keycloak.protocol.oid4vp.model.VerifiableCredential;

public interface VCSigningService<T> {

    T signCredential(VerifiableCredential verifiableCredential);
}
