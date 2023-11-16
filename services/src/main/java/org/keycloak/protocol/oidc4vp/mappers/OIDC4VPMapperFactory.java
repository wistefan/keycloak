package org.keycloak.protocol.oidc4vp.mappers;

import org.keycloak.models.ProtocolMapperModel;

public class OIDC4VPMapperFactory {

	private OIDC4VPMapperFactory() {
		// prevent instantiation
	}

	public static OIDC4VPMapper createOIDC4VPMapper(ProtocolMapperModel mapperModel) {
		return switch (mapperModel.getProtocolMapper()) {
			case OIDC4VPTargetRoleMapper.MAPPER_ID -> new OIDC4VPTargetRoleMapper().setMapperModel(mapperModel);
			case OIDC4VPSubjectIdMapper.MAPPER_ID -> new OIDC4VPSubjectIdMapper().setMapperModel(mapperModel);
			case OIDC4VPUserAttributeMapper.MAPPER_ID -> new OIDC4VPUserAttributeMapper().setMapperModel(mapperModel);
			case OIDC4VPStaticClaimMapper.MAPPER_ID -> new OIDC4VPStaticClaimMapper().setMapperModel(mapperModel);
			default -> throw new OIDC4VPMapperException(
					String.format("No mapper with id %s exists.", mapperModel.getProtocolMapper()));
		};
	}
}
