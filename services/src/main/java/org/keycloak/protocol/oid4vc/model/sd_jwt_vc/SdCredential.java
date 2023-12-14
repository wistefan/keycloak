package org.keycloak.protocol.oid4vc.model.sd_jwt_vc;

import com.fasterxml.jackson.annotation.JsonIgnore;

import java.util.ArrayList;
import java.util.List;

public class SdCredential {

    @JsonIgnore
    private List<SdClaim> sdClaims = new ArrayList<>();

    public List<SdClaim> getSdClaims() {
        return sdClaims;
    }

    public void setSdClaims(List<SdClaim> sdClaims) {
        this.sdClaims = sdClaims;
    }

    public void addSdClaim(SdClaim sdClaim) {
        sdClaims.add(sdClaim);
    }
}
