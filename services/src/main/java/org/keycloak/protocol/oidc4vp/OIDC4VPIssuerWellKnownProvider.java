package org.keycloak.protocol.oidc4vp;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.keycloak.models.KeycloakSession;
import org.keycloak.protocol.oidc4vp.model.CredentialIssuer;

public class OIDC4VPIssuerWellKnownProvider extends OIDC4VPAbstractWellKnownProvider {

	public OIDC4VPIssuerWellKnownProvider(KeycloakSession keycloakSession, ObjectMapper objectMapper) {
		super(keycloakSession, objectMapper);
	}

	@Override public void close() {
		// no-op
	}

	@Override public Object getConfig() {

		return new CredentialIssuer()
				.credentialIssuer(getIssuer(keycloakSession.getContext()))
				.credentialEndpoint(getCredentialsEndpoint(keycloakSession.getContext()))
				.credentialsSupported(getSupportedCredentials(keycloakSession.getContext()));
	}

}
