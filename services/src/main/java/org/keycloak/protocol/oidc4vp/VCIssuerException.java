package org.keycloak.protocol.oidc4vp;

public class VCIssuerException extends RuntimeException {

	public VCIssuerException(String message) {
		super(message);
	}

	public VCIssuerException(String message, Throwable cause) {
		super(message, cause);
	}
}
