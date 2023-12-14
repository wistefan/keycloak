package org.keycloak.protocol.oid4vp.model;


public enum ErrorType {

    INVALID_REQUEST("invalid_request"),
    INVALID_TOKEN("invalid_token"),
    UNSUPPORTED_CREDENTIAL_TYPE("unsupported_credential_type"),
    UNSUPPORTED_CREDENTIAL_FORMAT("unsupported_credential_format"),
    INVALID_OR_MISSING_PROOF("invalid_or_missing_proof");

    private final String value;

    ErrorType(String value) {
        this.value = value;
    }

    public String getValue() {
        return value;
    }
}
