package org.keycloak.protocol.oid4vp.model.sd_jwt_vc;

import static org.keycloak.protocol.oid4vp.signing.SdJwtSigningService.generateSalt;

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
