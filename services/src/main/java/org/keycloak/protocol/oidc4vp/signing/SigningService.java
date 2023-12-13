package org.keycloak.protocol.oidc4vp.signing;

import org.jboss.logging.Logger;

import java.time.Clock;
import java.util.Optional;

public abstract class SigningService<T> implements VCSigningService<T> {

    private static final Logger LOGGER = Logger.getLogger(SigningService.class);

    protected final KeyLoader keyLoader;
    protected final Optional<String> optionalKeyId;
    protected final Clock clock;
    // values of the type field are defined by the implementing service. Could f.e. the security suite for ldp_vc or the algorithm to be used for jwt_vc
    protected final String type;

    protected SigningService(KeyLoader keyLoader, Optional<String> optionalKeyId, Clock clock, String type) {
        this.keyLoader = keyLoader;
        this.optionalKeyId = optionalKeyId;
        this.clock = clock;
        this.type = type;
    }


}
