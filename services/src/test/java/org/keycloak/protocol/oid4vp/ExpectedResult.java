package org.keycloak.protocol.oid4vp;

import lombok.AllArgsConstructor;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.ToString;

@Getter
@RequiredArgsConstructor
@AllArgsConstructor
@EqualsAndHashCode
@ToString
public class ExpectedResult<T> {
	private final T expectedResult;
	private final String message;
	private Response response;

	@Getter
	@RequiredArgsConstructor
	@EqualsAndHashCode
	@ToString
	public static class Response {
		private final int code;
		private final boolean success;

	}
}
