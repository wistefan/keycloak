package org.keycloak.protocol.oid4vc.issuance.mappers;

import org.keycloak.models.ProtocolMapperModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.protocol.oid4vc.OID4VCClientRegistrationProviderFactory;
import org.keycloak.protocol.oid4vc.model.VerifiableCredential;
import org.keycloak.provider.ProviderConfigProperty;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Allows to add the context to the credential subject
 *
 * @author <a href="https://github.com/wistefan">Stefan Wiedemann</a>
 */
public class OID4VPContextMapper extends OID4VPMapper {

    public static final String MAPPER_ID = "oid4vc-context-mapper";
    public static final String TYPE_KEY = "context";

    private static final List<ProviderConfigProperty> CONFIG_PROPERTIES = new ArrayList<>();

    public OID4VPContextMapper() {
        super();
        ProviderConfigProperty contextPropertyNameConfig = new ProviderConfigProperty();
        contextPropertyNameConfig.setName(TYPE_KEY);
        contextPropertyNameConfig.setLabel("Verifiable Credentials Context");
        contextPropertyNameConfig.setHelpText("Context of the credential.");
        contextPropertyNameConfig.setType(ProviderConfigProperty.STRING_TYPE);
        contextPropertyNameConfig.setDefaultValue("https://www.w3.org/2018/credentials/v1");
        CONFIG_PROPERTIES.add(contextPropertyNameConfig);

    }

    @Override
    protected List<ProviderConfigProperty> getIndividualConfigProperties() {
        return CONFIG_PROPERTIES;
    }

    public static ProtocolMapperModel create(String name, String subjectId) {
        var mapperModel = new ProtocolMapperModel();
        mapperModel.setName(name);
        Map<String, String> configMap = new HashMap<>();
        configMap.put(SUPPORTED_CREDENTIALS_KEY, "VerifiableCredential");
        mapperModel.setConfig(configMap);
        mapperModel.setProtocol(OID4VCClientRegistrationProviderFactory.PROTOCOL_ID);
        mapperModel.setProtocolMapper(MAPPER_ID);
        return mapperModel;
    }

    public void setClaimsForCredential(VerifiableCredential verifiableCredential,
                                       UserSessionModel userSessionModel) {
        // remove duplicates
        Set<String> contexts = new HashSet<>();
        if (verifiableCredential.getContext() != null) {
            contexts = new HashSet<>(verifiableCredential.getContext());
        }
        contexts.add(mapperModel.getConfig().get(TYPE_KEY));
        verifiableCredential.setContext(new ArrayList<>(contexts));
    }

    @Override
    public void setClaimsForSubject(Map<String, Object> claims, UserSessionModel userSessionModel) {
        // nothing to do for the mapper.
    }

    @Override
    public String getDisplayType() {
        return "Credential Context Mapper";
    }

    @Override
    public String getHelpText() {
        return "Assigns a context to the credential.";
    }

    @Override
    public String getId() {
        return MAPPER_ID;
    }
}
