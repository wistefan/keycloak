package org.keycloak.protocol.oid4vp;

import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.DELETE;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.PUT;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import org.jboss.logging.Logger;
import org.keycloak.models.KeycloakSession;
import org.keycloak.representations.idm.ClientRepresentation;
import org.keycloak.services.ErrorResponseException;
import org.keycloak.services.clientregistration.AbstractClientRegistrationProvider;

import java.net.URI;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.stream.Collectors;

/**
 * Provides the client-registration functionality for OIDC4VP-clients.
 */
public class OIDC4VPClientRegistrationProvider extends AbstractClientRegistrationProvider {

	private static final Logger LOGGER = Logger.getLogger(OIDC4VPClientRegistrationProvider.class);

	public static final String VC_CLAIMS_PREFIX = "vc_";
	public static final String VC_TYPES_PREFIX = "vctypes_";

	public OIDC4VPClientRegistrationProvider(KeycloakSession session) {
		super(session);
	}

	// CUD implementations for the SIOP-2 client

	@POST
	@Consumes(MediaType.APPLICATION_JSON)
	@Produces(MediaType.APPLICATION_JSON)
	public Response createOIDC4VPClient(OIDC4VPClient client) {
		LOGGER.infof("Create siop client %s", client);
		ClientRepresentation clientRepresentation = toClientRepresentation(client);
		validate(clientRepresentation);

		ClientRepresentation cr = create(
				new OIDC4VPClientRegistrationContext(session, clientRepresentation, this));
		URI uri = session.getContext().getUri().getAbsolutePathBuilder().path(cr.getClientId()).build();
		return Response.created(uri).entity(cr).build();
	}

	@PUT
	@Path("{clientId}")
	@Consumes(MediaType.APPLICATION_JSON)
	@Produces(MediaType.APPLICATION_JSON)
	public Response updateOIDC4VPClient(@PathParam("clientId") String clientDid, OIDC4VPClient client) {
		client.setClientDid(clientDid);
		ClientRepresentation clientRepresentation = toClientRepresentation(client);
		validate(clientRepresentation);
		clientRepresentation = update(clientDid,
				new OIDC4VPClientRegistrationContext(session, clientRepresentation, this));
		return Response.ok(clientRepresentation).build();
	}

	@DELETE
	@Path("{clientId}")
	public Response deleteOIDC4VPClient(@PathParam("clientId") String clientDid) {
		delete(clientDid);
		return Response.noContent().build();
	}

	/**
	 * Validates the clientrepresentation to fulfill the requirement of a OIDC4VP client
	 *
	 * @param client
	 */
	public static void validate(ClientRepresentation client) {
		String did = client.getClientId();
		if (did == null) {
			throw new ErrorResponseException("no_did", "A client did needs to be configured for SIOP-2 clients",
					Response.Status.BAD_REQUEST);
		}
		if (!did.startsWith("did:")) {
			throw new ErrorResponseException("invalid_did", "The client did is not a valid did.",
					Response.Status.BAD_REQUEST);
		}
	}

	/**
	 * Translate an incoming {@link OIDC4VPClient} into a keycloak native {@link ClientRepresentation}.
	 *
	 * @param oidc4VPClient pojo, containing the SIOP-2 client parameters
	 * @return a clientrepresentation, fitting keycloaks internal model
	 */
	protected static ClientRepresentation toClientRepresentation(OIDC4VPClient oidc4VPClient) {
		ClientRepresentation clientRepresentation = new ClientRepresentation();
		// protocol needs to be SIOP-2
		clientRepresentation.setProtocol(OIDC4VPClientRegistrationProviderFactory.PROTOCOL_ID);
		// id and clientId cannot be equal since did's might be to long, already validated to be non-null
		clientRepresentation.setId(UUID.randomUUID().toString());
		clientRepresentation.setClientId(oidc4VPClient.getClientDid());
		// only add non-null parameters
		Optional.ofNullable(oidc4VPClient.getDescription()).ifPresent(clientRepresentation::setDescription);
		Optional.ofNullable(oidc4VPClient.getName()).ifPresent(clientRepresentation::setName);

		// add potential additional claims
		Map<String, String> clientAttributes = new HashMap<>(
				prefixClaims(VC_CLAIMS_PREFIX, oidc4VPClient.getAdditionalClaims()));

		// only set supported VCs if present
		if (oidc4VPClient.getSupportedVCTypes() != null) {
			oidc4VPClient.getSupportedVCTypes()
					.forEach(supportedCredential -> {
						String typeKey = Optional.ofNullable(supportedCredential.getId())
								.orElse(String.format("%s%s", VC_TYPES_PREFIX, supportedCredential.getTypes().get(0)));
						if (clientAttributes.containsKey(typeKey)) {
							clientAttributes.put(typeKey, String.format("%s,%s",
									clientAttributes.get(typeKey),
									supportedCredential.getFormat().toString()));
						} else {
							clientAttributes.put(typeKey,
									supportedCredential.getFormat().toString());
						}
					});
		}
		if (!clientAttributes.isEmpty()) {
			clientRepresentation.setAttributes(clientAttributes);
		}

		LOGGER.debugf("Generated client representation {}.", clientRepresentation);
		return clientRepresentation;
	}

	/**
	 * Prefix the map of claims, to differentiate them from potential internal once. Only the prefixed claims will be
	 * used for creating VCs.
	 */
	private static Map<String, String> prefixClaims(String prefix, Map<String, String> claimsToPrefix) {
		if (claimsToPrefix == null) {
			return Map.of();
		}
		return claimsToPrefix.entrySet()
				.stream()
				.collect(
						Collectors
								.toMap(e -> String.format("%s%s", prefix, e.getKey()),
										Map.Entry::getValue));
	}
}
