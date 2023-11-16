package org.keycloak.protocol.oidc4vp.model;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;

@AllArgsConstructor
@NoArgsConstructor
@Getter
public class CredentialOfferURI {
    private String issuer;
    private String nonce;
}
