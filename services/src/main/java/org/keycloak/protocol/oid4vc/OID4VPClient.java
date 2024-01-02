package org.keycloak.protocol.oid4vc;

import org.keycloak.protocol.oid4vc.model.SupportedCredential;

import java.util.List;
import java.util.Map;

/**
 * Pojo, containing all information required to create a VCClient.
 *
 * @author <a href="https://github.com/wistefan">Stefan Wiedemann</a>
 */
public class OID4VPClient {

    /**
     * Did of the target/client, will be used as client-id
     */
    private String clientDid;
    /**
     * Comma-separated list of supported credentials types
     */
    private List<SupportedCredential> supportedVCTypes;
    /**
     * Description of the client, will f.e. be displayed in the admin-console
     */
    private String description;
    /**
     * Human-readable name of the client
     */
    private String name;
    /**
     * Expiry for the credentials to be created.
     * Be aware: this used the non-primitive long to stay nullable.
     */
    private Long expiryInMin;
    /**
     * A map of additional claims that will be provided within the generated VC.
     */
    private Map<String, String> additionalClaims;

    public OID4VPClient() {
    }

    public OID4VPClient(String clientDid, List<SupportedCredential> supportedVCTypes, String description, String name, Long expiryInMin, Map<String, String> additionalClaims) {
        this.clientDid = clientDid;
        this.supportedVCTypes = supportedVCTypes;
        this.description = description;
        this.name = name;
        this.expiryInMin = expiryInMin;
        this.additionalClaims = additionalClaims;
    }

    public String getClientDid() {
        return clientDid;
    }

    public void setClientDid(String clientDid) {
        this.clientDid = clientDid;
    }

    public List<SupportedCredential> getSupportedVCTypes() {
        return supportedVCTypes;
    }

    public void setSupportedVCTypes(List<SupportedCredential> supportedVCTypes) {
        this.supportedVCTypes = supportedVCTypes;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public Long getExpiryInMin() {
        return expiryInMin;
    }

    public void setExpiryInMin(Long expiryInMin) {
        this.expiryInMin = expiryInMin;
    }

    public Map<String, String> getAdditionalClaims() {
        return additionalClaims;
    }

    public void setAdditionalClaims(Map<String, String> additionalClaims) {
        this.additionalClaims = additionalClaims;
    }
}
