package org.keycloak.protocol.oid4vc.issuance.mappers;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.validation.constraints.NotNull;
import org.jboss.logging.Logger;
import org.keycloak.models.ClientModel;
import org.keycloak.models.ProtocolMapperModel;
import org.keycloak.models.RoleModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.protocol.oid4vc.OID4VCClientRegistrationProviderFactory;
import org.keycloak.protocol.oid4vc.model.Role;
import org.keycloak.protocol.oid4vc.model.VerifiableCredential;
import org.keycloak.provider.ProviderConfigProperty;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Adds the users roles to the credential subject
 *
 * @author <a href="https://github.com/wistefan">Stefan Wiedemann</a>
 */
public class OID4VPTargetRoleMapper extends OID4VPMapper {

    private static final Logger LOGGER = Logger.getLogger(OID4VPTargetRoleMapper.class);
    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

    public static final String MAPPER_ID = "oid4vc-target-role-mapper";
    public static final String SUBJECT_PROPERTY_CONFIG_KEY = "subjectProperty";
    public static final String CLIENT_CONFIG_KEY = "clientId";

    private static final List<ProviderConfigProperty> CONFIG_PROPERTIES = new ArrayList<>();

    public OID4VPTargetRoleMapper() {
        super();
        ProviderConfigProperty subjectPropertyNameConfig = new ProviderConfigProperty();
        subjectPropertyNameConfig.setName(SUBJECT_PROPERTY_CONFIG_KEY);
        subjectPropertyNameConfig.setLabel("Roles Property Name");
        subjectPropertyNameConfig.setHelpText("Property to add the roles to in the credential subject.");
        subjectPropertyNameConfig.setDefaultValue("roles");
        subjectPropertyNameConfig.setType(ProviderConfigProperty.STRING_TYPE);
        CONFIG_PROPERTIES.add(subjectPropertyNameConfig);
    }

    @Override
    protected List<ProviderConfigProperty> getIndividualConfigProperties() {
        return CONFIG_PROPERTIES;
    }

    @Override
    public String getDisplayType() {
        return "Target-Role Mapper";
    }

    @Override
    public String getHelpText() {
        return "Map the assigned role to the credential subject, providing the client id as the target.";
    }

    public static ProtocolMapperModel create(String clientId, String name) {
        var mapperModel = new ProtocolMapperModel();
        mapperModel.setName(name);
        Map<String, String> configMap = new HashMap<>();
        configMap.put(SUBJECT_PROPERTY_CONFIG_KEY, "roles");
        configMap.put(CLIENT_CONFIG_KEY, clientId);
        mapperModel.setConfig(configMap);
        mapperModel.setProtocol(OID4VCClientRegistrationProviderFactory.PROTOCOL_ID);
        mapperModel.setProtocolMapper(MAPPER_ID);
        return mapperModel;
    }

    @Override
    public String getId() {
        return MAPPER_ID;
    }

    @Override
    public void setClaimsForCredential(VerifiableCredential verifiableCredential,
                                       UserSessionModel userSessionModel) {
        // nothing to do for the mapper.
    }

    @Override
    public void setClaimsForSubject(Map<String, Object> claims,
                                    UserSessionModel userSessionModel) {
        String client = mapperModel.getConfig().get(CLIENT_CONFIG_KEY);
        String propertyName = mapperModel.getConfig().get(SUBJECT_PROPERTY_CONFIG_KEY);
        LOGGER.infof("Client is %s", client);
        ClientModel clientModel = userSessionModel.getRealm().getClientByClientId(client);
        if (clientModel == null || !clientModel.getProtocol().equals(OID4VCClientRegistrationProviderFactory.PROTOCOL_ID)) {
            return;
        }

        ClientRoleModel clientRoleModel = new ClientRoleModel(clientModel.getClientId(),
                userSessionModel.getUser().getClientRoleMappingsStream(clientModel).toList());
        Role rolesClaim = toRolesClaim(clientRoleModel);
        if (rolesClaim.getNames().isEmpty()) {
            return;
        }
        var modelMap = OBJECT_MAPPER.convertValue(toRolesClaim(clientRoleModel), Map.class);

        if (claims.containsKey(propertyName)) {
            if (claims.get(propertyName) instanceof Set rolesProperty) {
                rolesProperty.add(modelMap);
                claims.put(propertyName, rolesProperty);
            } else {
                LOGGER.warnf("Incompatible types for property %s. The mapper will not set the roles for client %s",
                        propertyName, client);
            }
        } else {
            // needs to be mutable
            Set roles = new HashSet();
            roles.add(modelMap);
            claims.put(propertyName, roles);
        }
    }

    @NotNull
    private Role toRolesClaim(ClientRoleModel crm) {
        Set<String> roleNames = crm
                .getRoleModels()
                .stream()
                .map(RoleModel::getName)
                .collect(Collectors.toSet());
        return new Role(roleNames, crm.getClientId());
    }

    private static class ClientRoleModel {
        private final String clientId;
        private final List<RoleModel> roleModels;

        public ClientRoleModel(String clientId, List<RoleModel> roleModels) {
            this.clientId = clientId;
            this.roleModels = roleModels;
        }

        public String getClientId() {
            return clientId;
        }

        public List<RoleModel> getRoleModels() {
            return roleModels;
        }
    }
}
