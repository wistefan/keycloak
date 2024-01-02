package org.keycloak.protocol.oid4vc.model.sd_jwt_vc;

public class ArrayElement {

    private String disclosure;
    private String digest;
    private String salt;
    private Object value;

    public ArrayElement(String salt, Object value) {
        this.salt = salt;
        this.value = value;
    }

    public String getSalt() {
        return salt;
    }

    public void setSalt(String salt) {
        this.salt = salt;
    }

    public Object getValue() {
        return value;
    }

    public void setValue(Object value) {
        this.value = value;
    }

    public String getDisclosure() {
        return disclosure;
    }

    public void setDisclosure(String disclosure) {
        this.disclosure = disclosure;
    }

    public String getDigest() {
        return digest;
    }

    public void setDigest(String digest) {
        this.digest = digest;
    }

    public ArrayDigest asDigest() {
        return new ArrayDigest(this.digest);
    }
}
