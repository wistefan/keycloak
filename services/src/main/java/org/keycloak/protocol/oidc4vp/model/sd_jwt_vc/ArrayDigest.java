package org.keycloak.protocol.oidc4vp.model.sd_jwt_vc;

import com.fasterxml.jackson.annotation.JsonProperty;

public class ArrayDigest {

    @JsonProperty("...")
    private String digest;

    public ArrayDigest() {
    }

    public ArrayDigest(String digest) {
        this.digest = digest;
    }

    public String getDigest() {
        return digest;
    }

    public void setDigest(String digest) {
        this.digest = digest;
    }
}
