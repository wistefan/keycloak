package org.keycloak.protocol.oid4vp.signing;

public class SigningServiceException extends RuntimeException{

	public SigningServiceException(String message) {
		super(message);
	}

	public SigningServiceException(String message, Throwable cause) {
		super(message, cause);
	}
}
