package org.keycloak.protocol.oid4vc.issuance;

public class VCIssuerException extends RuntimeException {

	public VCIssuerException(String message) {
		super(message);
	}

	public VCIssuerException(String message, Throwable cause) {
		super(message, cause);
	}
}
