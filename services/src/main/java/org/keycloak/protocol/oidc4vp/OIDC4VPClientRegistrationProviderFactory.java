package org.keycloak.protocol.oidc4vp;

import org.keycloak.Config;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.services.clientregistration.ClientRegistrationProvider;
import org.keycloak.services.clientregistration.ClientRegistrationProviderFactory;

import java.util.List;

/**
 * Empty implementation of the {@link ClientRegistrationProviderFactory} to integrate the SIOP-2 protocol with
 * Keycloaks client-registration.
 */
public class OIDC4VPClientRegistrationProviderFactory implements ClientRegistrationProviderFactory {

	public static final String PROTOCOL_ID = "OIDC4VP";

	@Override public ClientRegistrationProvider create(KeycloakSession session) {
		return new OIDC4VPClientRegistrationProvider(session);
	}

	@Override public void init(Config.Scope config) {
		// no config required
	}

	@Override public void postInit(KeycloakSessionFactory factory) {
		// nothing to do post init
	}

	@Override public void close() {
		// no resources to close
	}

	@Override public String getId() {
		return OIDC4VPClientRegistrationProviderFactory.PROTOCOL_ID;
	}

	@Override public List<ProviderConfigProperty> getConfigMetadata() {
		ProviderConfigProperty issuerDid = new ProviderConfigProperty();
		issuerDid.setName("issuer_did");
		issuerDid.setHelpText("DID to be used for issuing verifiable credentials.");
		issuerDid.setType(ProviderConfigProperty.STRING_TYPE);
		issuerDid.setLabel("Issuer DID");

		ProviderConfigProperty keyPath = new ProviderConfigProperty();
		keyPath.setName("key_path");
		keyPath.setHelpText("Path to read the signing key from.");
		keyPath.setType(ProviderConfigProperty.STRING_TYPE);
		keyPath.setLabel("Key Path");

		return List.of(issuerDid, keyPath);
	}
}
