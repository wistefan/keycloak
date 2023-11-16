package org.keycloak.protocol.oidc4vp.model;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Data;

@Data
public class RequestProof {

	@JsonProperty("proof_type")
	private ProofTypeVO proofType;
	private String jwt;
}
