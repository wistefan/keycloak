package org.keycloak.protocol.oid4vc.issuance.signing;

import java.time.Clock;
import java.util.Optional;

public abstract class SigningService<T> implements VCSigningService<T> {

    protected final KeyLoader keyLoader;
    protected final String keyId;
    protected final Clock clock;
    // values of the type field are defined by the implementing service. Could f.e. the security suite for ldp_vc or the algorithm to be used for jwt_vc
    protected final String type;

    protected SigningService(KeyLoader keyLoader, String keyId, Clock clock, String type) {
        this.keyLoader = keyLoader;
        this.keyId = keyId;
        this.clock = clock;
        this.type = type;
    }


}
