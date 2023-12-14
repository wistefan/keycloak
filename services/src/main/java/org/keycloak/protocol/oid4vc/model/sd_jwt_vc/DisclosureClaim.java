package org.keycloak.protocol.oid4vc.model.sd_jwt_vc;

public class DisclosureClaim {

    private String digest;
    private String disclosure;
    private String salt;
    private String key;

    public DisclosureClaim() {
    }

    public DisclosureClaim(String digest, String disclosure, String salt, String key) {
        this.digest = digest;
        this.disclosure = disclosure;
        this.salt = salt;
        this.key = key;
    }

    public String getDigest() {
        return digest;
    }

    public void setDigest(String digest) {
        this.digest = digest;
    }

    public String getDisclosure() {
        return disclosure;
    }

    public void setDisclosure(String disclosure) {
        this.disclosure = disclosure;
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

}
