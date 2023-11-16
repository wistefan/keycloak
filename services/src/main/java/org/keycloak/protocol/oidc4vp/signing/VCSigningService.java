package org.keycloak.protocol.oidc4vp.signing;

import com.danubetech.verifiablecredentials.VerifiableCredential;

public interface VCSigningService<T> {

	T signCredential(VerifiableCredential verifiableCredential);
}
