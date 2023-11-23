package org.keycloak.protocol.oidc4vp.mappers;

import com.danubetech.verifiablecredentials.VerifiableCredential;
import org.keycloak.models.ProtocolMapperModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.protocol.oidc4vp.OIDC4VPClientRegistrationProviderFactory;
import org.keycloak.provider.ProviderConfigProperty;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

public class OIDC4VPSubjectIdMapper extends OIDC4VPMapper {

	public static final String MAPPER_ID = "oidc4vp-subject-id-mapper";
	public static final String ID_KEY = "subjectIdProperty";

	private static final List<ProviderConfigProperty> CONFIG_PROPERTIES = new ArrayList<>();

	public OIDC4VPSubjectIdMapper() {
		super();
		ProviderConfigProperty idPropertyNameConfig = new ProviderConfigProperty();
		idPropertyNameConfig.setName(ID_KEY);
		idPropertyNameConfig.setLabel("ID Property Name");
		idPropertyNameConfig.setHelpText("Name of the property to contain the id.");
		idPropertyNameConfig.setDefaultValue("id");
		idPropertyNameConfig.setType(ProviderConfigProperty.STRING_TYPE);
		CONFIG_PROPERTIES.add(idPropertyNameConfig);

	}

	@Override protected List<ProviderConfigProperty> getIndividualConfigProperties() {
		return CONFIG_PROPERTIES;
	}

	public static ProtocolMapperModel create(String name, String subjectId) {
		var mapperModel = new ProtocolMapperModel();
		mapperModel.setName(name);
		Map<String, String> configMap = new HashMap<>();
		configMap.put(ID_KEY, subjectId);
		configMap.put(SUPPORTED_CREDENTIALS_KEY, "VerifiableCredential");
		mapperModel.setConfig(configMap);
		mapperModel.setProtocol(OIDC4VPClientRegistrationProviderFactory.PROTOCOL_ID);
		mapperModel.setProtocolMapper(MAPPER_ID);
		return mapperModel;
	}

	@Override public void setClaimsForCredential(VerifiableCredential.Builder credentialBuilder,
			UserSessionModel userSessionModel) {
		// nothing to do for the mapper.
	}

	@Override public void setClaimsForSubject(Map<String, Object> claims, UserSessionModel userSessionModel) {
		claims.put("id", mapperModel.getConfig().getOrDefault(ID_KEY, String.format("urn:uuid:%s", UUID.randomUUID())));
	}

	@Override public String getDisplayType() {
		return "CredentialSubject ID Mapper";
	}

	@Override public String getHelpText() {
		return "Assigns a subject ID to the credentials subject. If no specific id is configured, a randomly generated one is used.";
	}

	@Override public String getId() {
		return MAPPER_ID;
	}
}
