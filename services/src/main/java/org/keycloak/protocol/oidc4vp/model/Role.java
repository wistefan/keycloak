package org.keycloak.protocol.oidc4vp.model;

import lombok.AllArgsConstructor;
import lombok.Data;

import java.util.Set;

@AllArgsConstructor
@Data
public class Role {

	private Set<String> names;
	private String target;

}
