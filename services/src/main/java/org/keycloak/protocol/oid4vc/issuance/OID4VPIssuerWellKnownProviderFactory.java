package org.keycloak.protocol.oid4vc.issuance;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.jboss.logging.Logger;
import org.keycloak.Config;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.wellknown.WellKnownProvider;
import org.keycloak.wellknown.WellKnownProviderFactory;

/**
 * {@link  WellKnownProviderFactory} implementation for the OID4VCI metadata
 *
 * {@see https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-10.2.2}
 *
 * @author <a href="https://github.com/wistefan">Stefan Wiedemann</a>
 */
public class OID4VPIssuerWellKnownProviderFactory implements WellKnownProviderFactory {
    private static final Logger LOGGER = Logger.getLogger(OID4VPIssuerWellKnownProviderFactory.class);
    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

    public static final String PROVIDER_ID = "openid-credential-issuer";

    @Override
    public WellKnownProvider create(KeycloakSession session) {
        return new OID4VPIssuerWellKnownProvider(session, OBJECT_MAPPER);
    }

    @Override
    public void init(Config.Scope config) {
        LOGGER.info("Oidc4vp issuer");
        // no-op
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {
        // no-op
    }

    @Override
    public void close() {
        // no-op
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }
}
