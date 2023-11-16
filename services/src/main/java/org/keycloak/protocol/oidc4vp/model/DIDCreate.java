package org.keycloak.protocol.oidc4vp.model;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@AllArgsConstructor
@NoArgsConstructor
@Data
public class DIDCreate {

	private String method = "key";
}
