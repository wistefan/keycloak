package org.keycloak.protocol.oidc4vp.model;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class SupportedCredential {

	public String type;
	public FormatVO format;
}
