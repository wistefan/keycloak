package org.keycloak.protocol.oidc4vp.model.sd_jwt_vc;

import java.util.ArrayList;
import java.util.List;

public class ArrayDisclosureClaim {

    private String key;
    private List<ArrayElement> values = new ArrayList<>();

    public ArrayDisclosureClaim() {
    }

    public ArrayDisclosureClaim(String key) {
        this.key = key;
    }

    public String getKey() {
        return key;
    }

    public void setKey(String key) {
        this.key = key;
    }

    public List<ArrayElement> getValues() {
        return values;
    }

    public void setValues(List<ArrayElement> values) {
        this.values = values;
    }

    public void addValue(ArrayElement value) {
        this.values.add(value);
    }
}
