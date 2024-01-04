package org.keycloak.protocol.oid4vc.issuance;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.keycloak.models.KeycloakSession;
import org.keycloak.protocol.oid4vc.OID4VPAbstractWellKnownProvider;
import org.keycloak.protocol.oid4vc.model.CredentialIssuer;
import org.keycloak.wellknown.WellKnownProvider;

/**
 * {@link  WellKnownProvider} implementation to provide the .well-known/openid-credential-issuer endpoint, offering
 * the Credential Issuer Metadata as defined by the OID4VCI protocol
 * {@see https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-10.2.2}
 *
 * @author <a href="https://github.com/wistefan">Stefan Wiedemann</a>
 */
public class OID4VPIssuerWellKnownProvider extends OID4VPAbstractWellKnownProvider {

    public OID4VPIssuerWellKnownProvider(KeycloakSession keycloakSession, ObjectMapper objectMapper) {
        super(keycloakSession, objectMapper);
    }

    @Override
    public void close() {
        // no-op
    }

    @Override
    public Object getConfig() {

        return new CredentialIssuer()
                .credentialIssuer(getIssuer(keycloakSession.getContext()))
                .credentialEndpoint(getCredentialsEndpoint(keycloakSession.getContext()))
                .credentialsSupported(getSupportedCredentials(keycloakSession));
    }

}
