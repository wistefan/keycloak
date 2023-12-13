package org.keycloak.protocol.oidc4vp.signing;


import org.keycloak.protocol.oidc4vp.model.VerifiableCredential;

public interface VCSigningService<T> {

    T signCredential(VerifiableCredential verifiableCredential);
}
