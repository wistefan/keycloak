package org.keycloak.protocol.oid4vc.issuance;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.jboss.logging.Logger;
import org.keycloak.Config;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.wellknown.WellKnownProvider;
import org.keycloak.wellknown.WellKnownProviderFactory;

public class OIDC4VPWellKnownProviderFactory implements WellKnownProviderFactory {


	private static final Logger LOGGER = Logger.getLogger(OIDC4VPWellKnownProviderFactory.class);
	private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

	public static final String PROVIDER_ID = "openid-configuration";

	@Override public WellKnownProvider create(KeycloakSession session) {
		return new OIDC4VPWellKnownProvider(session, OBJECT_MAPPER);
	}

	@Override public void init(Config.Scope config) {
		LOGGER.info("Oidc4vp well known");
		// no-op

	}

	@Override public void postInit(KeycloakSessionFactory factory) {
		// no-op
	}

	@Override public void close() {
		// no-op

	}

	@Override public int getPriority() {
		return 0;
	}

	@Override public String getId() {
		return PROVIDER_ID;
	}
}
