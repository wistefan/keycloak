package org.keycloak.protocol.oidc4vp.mappers;

public class OIDC4VPMapperException extends RuntimeException {
	public OIDC4VPMapperException(String message) {
		super(message);
	}

	public OIDC4VPMapperException(String message, Throwable cause) {
		super(message, cause);
	}
}
