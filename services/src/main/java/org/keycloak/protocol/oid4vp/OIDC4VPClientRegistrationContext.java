package org.keycloak.protocol.oid4vp;

import org.keycloak.models.KeycloakSession;
import org.keycloak.representations.idm.ClientRepresentation;
import org.keycloak.services.clientregistration.AbstractClientRegistrationContext;
import org.keycloak.services.clientregistration.ClientRegistrationProvider;

/**
 * Empty registration context to fulfill client-registration integration.
 */
public class OIDC4VPClientRegistrationContext extends AbstractClientRegistrationContext {

	public OIDC4VPClientRegistrationContext(KeycloakSession session,
			ClientRepresentation client,
			ClientRegistrationProvider provider) {
		super(session, client, provider);
	}
}
