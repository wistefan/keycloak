package org.keycloak.protocol.oidc4vp.mappers;

import com.danubetech.verifiablecredentials.VerifiableCredential;
import org.jboss.logging.Logger;
import org.keycloak.Config;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.ProtocolMapperModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.protocol.ProtocolMapper;
import org.keycloak.protocol.oidc4vp.OIDC4VPLoginProtocolFactory;
import org.keycloak.provider.ProviderConfigProperty;

import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Stream;

public abstract class OIDC4VPMapper implements ProtocolMapper {

	private static final Logger LOGGER = Logger.getLogger(OIDC4VPMapper.class);

	protected static final String SUPPORTED_CREDENTIALS_KEY = "supportedCredentialTypes";

	protected ProtocolMapperModel mapperModel;

	private static List<ProviderConfigProperty> SIOP_CONFIG_PROPERTIES;

	{
		ProviderConfigProperty supportedCredentialsConfig = new ProviderConfigProperty();
		supportedCredentialsConfig.setType(ProviderConfigProperty.STRING_TYPE);
		supportedCredentialsConfig.setLabel("Supported Credential Types");
		supportedCredentialsConfig.setDefaultValue("VerifiableCredential");
		supportedCredentialsConfig.setHelpText(
				"Types of Credentials to apply the mapper. Needs to be a comma-seperated list.");
		supportedCredentialsConfig.setName(SUPPORTED_CREDENTIALS_KEY);
		SIOP_CONFIG_PROPERTIES = List.of(supportedCredentialsConfig);
	}

	protected abstract List<ProviderConfigProperty> getIndividualConfigProperties();

	@Override public List<ProviderConfigProperty> getConfigProperties() {
		return Stream.concat(SIOP_CONFIG_PROPERTIES.stream(), getIndividualConfigProperties().stream()).toList();
	}

	public OIDC4VPMapper setMapperModel(ProtocolMapperModel mapperModel) {
		this.mapperModel = mapperModel;
		return this;
	}

	@Override public String getProtocol() {
		return OIDC4VPLoginProtocolFactory.PROTOCOL_ID;
	}

	@Override public ProtocolMapper create(KeycloakSession session) {
		throw new OIDC4VPMapperException("UNSUPPORTED METHOD");
	}

	@Override public String getDisplayCategory() {
		return "OIDC4VP Mapper";
	}

	@Override public void init(Config.Scope scope) {
	}

	@Override public void postInit(KeycloakSessionFactory keycloakSessionFactory) {
		// try to get the credentials
	}

	@Override public void close() {
	}

	/**
	 * Checks if the mapper supports the given credential type. Allows to configure them not only per client, but also per VC Type.
	 *
	 * @param credentialType type of the VerifiableCredential that should be checked
	 * @return true if it is supported
	 */
	public boolean isTypeSupported(String credentialType) {
		var optionalTypes = Optional.ofNullable(mapperModel.getConfig().get(SUPPORTED_CREDENTIALS_KEY));
		if (optionalTypes.isEmpty()) {
			return false;
		}
		return Arrays.asList(optionalTypes.get().split(",")).contains(credentialType);
	}

	/**
	 * Set the claims to credential, like f.e. the context
	 */
	public abstract void setClaimsForCredential(VerifiableCredential.Builder credentialBuilder,
			UserSessionModel userSessionModel);

	/**
	 * Set the claims to the credential subject.
	 */
	public abstract void setClaimsForSubject(Map<String, Object> claims,
			UserSessionModel userSessionModel);

}
