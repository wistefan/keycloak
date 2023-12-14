package org.keycloak.protocol.oid4vp.model;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.Set;

@AllArgsConstructor
@Data
@NoArgsConstructor
public class Role {

	private Set<String> names;
	private String target;

}
