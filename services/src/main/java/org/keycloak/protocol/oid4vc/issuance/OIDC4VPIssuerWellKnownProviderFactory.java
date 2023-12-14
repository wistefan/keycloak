package org.keycloak.protocol.oid4vc.issuance;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.jboss.logging.Logger;
import org.keycloak.Config;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.wellknown.WellKnownProvider;
import org.keycloak.wellknown.WellKnownProviderFactory;

public class OIDC4VPIssuerWellKnownProviderFactory implements WellKnownProviderFactory {
	private static final Logger LOGGER = Logger.getLogger(OIDC4VPIssuerWellKnownProviderFactory.class);
	private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

	public static final String PROVIDER_ID = "openid-credential-issuer";

	@Override public WellKnownProvider create(KeycloakSession session) {
		return new OIDC4VPIssuerWellKnownProvider(session, OBJECT_MAPPER);
	}

	@Override public void init(Config.Scope config) {
		LOGGER.info("Oidc4vp issuer");
		// no-op
	}

	@Override public void postInit(KeycloakSessionFactory factory) {
		// no-op
	}

	@Override public void close() {
		// no-op
	}

	@Override public String getId() {
		return PROVIDER_ID;
	}
}
