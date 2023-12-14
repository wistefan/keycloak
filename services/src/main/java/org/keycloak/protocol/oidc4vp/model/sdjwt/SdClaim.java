package org.keycloak.protocol.oidc4vp.model.sdjwt;

import org.keycloak.common.util.Base64;
import org.keycloak.protocol.oidc4vp.signing.SigningServiceException;

import java.io.IOException;
import java.security.SecureRandom;

import static org.keycloak.protocol.oidc4vp.signing.SdJwtSigningService.generateSalt;

public class SdClaim {

    private String salt;
    private String key;
    private Object value;

    public SdClaim(String key, Object value) {

        this.key = key;
        this.value = value;
        this.salt = generateSalt();
    }


    public String getSalt() {
        return salt;
    }

    public void setSalt(String salt) {
        this.salt = salt;
    }

    public String getKey() {
        return key;
    }

    public void setKey(String key) {
        this.key = key;
    }

    public Object getValue() {
        return value;
    }

    public void setValue(Object value) {
        this.value = value;
    }


}
