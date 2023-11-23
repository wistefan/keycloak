package org.keycloak.protocol.oidc4vp.signing;

import java.util.List;

public enum AlgorithmType {

	ED_DSA_ED25519(List.of("eddsa", "ed25519", "eddsa_ed25519")),
	ECDSA_SECP256K1(List.of("ecdsa", "secp256k1", "ecdsa_secp256k1")),
	RSA(List.of("rsa", "ps256", "rs256"));

	private final List<String> values;

	AlgorithmType(List<String> values) {
		this.values = values;
	}

	public List<String> getValues() {
		return values;
	}

	public static AlgorithmType getByValue(String value) {
		for (AlgorithmType algorithmType : values())
			if (algorithmType.values.stream().anyMatch(value::equalsIgnoreCase)) {
				return algorithmType;
			}
		throw new IllegalArgumentException(String.format("No algorithm of type %s exists.", value));
	}
}
