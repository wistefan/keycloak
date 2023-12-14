package org.keycloak.protocol.oidc4vp.model;

import com.fasterxml.jackson.annotation.*;
import org.keycloak.protocol.oidc4vp.model.vcdm.LdProof;

import java.net.URI;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@JsonInclude(JsonInclude.Include.NON_NULL)
public class VerifiableCredential {

    @JsonProperty("@context")
    private List<String> context;
    private List<String> type;
    private URI issuer;
    private Date issuanceDate;
    private URI id;
    private Date expirationDate;
    private CredentialSubject credentialSubject = new CredentialSubject();
    private LdProof proof;
    @JsonIgnore
    private Map<String, Object> additionalProperties = new HashMap<>();

    @JsonAnyGetter
    public Map<String, Object> getAdditionalProperties() {
        return additionalProperties;
    }

    @JsonAnySetter
    public void setAdditionalProperties(String name, Object property) {
        additionalProperties.put(name, property);
    }

    public List<String> getContext() {
        return context;
    }

    public void setContext(List<String> context) {
        this.context = context;
    }

    public List<String> getType() {
        return type;
    }

    public void setType(List<String> type) {
        this.type = type;
    }

    public URI getIssuer() {
        return issuer;
    }

    public void setIssuer(URI issuer) {
        this.issuer = issuer;
    }

    public Date getIssuanceDate() {
        return issuanceDate;
    }

    public void setIssuanceDate(Date issuanceDate) {
        this.issuanceDate = issuanceDate;
    }

    public Date getExpirationDate() {
        return expirationDate;
    }

    public void setExpirationDate(Date expirationDate) {
        this.expirationDate = expirationDate;
    }

    public CredentialSubject getCredentialSubject() {
        return credentialSubject;
    }

    public void setCredentialSubject(CredentialSubject credentialSubject) {
        this.credentialSubject = credentialSubject;
    }

    public LdProof getProof() {
        return proof;
    }

    public void setProof(LdProof proof) {
        this.proof = proof;
    }

    public URI getId() {
        return id;
    }

    public void setId(URI id) {
        this.id = id;
    }
}
