package org.keycloak.protocol.oid4vc;

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
 * Provides the client-registration functionality for OID4VP-clients.
 *
 * @author <a href="https://github.com/wistefan">Stefan Wiedemann</a>
 */
public class OID4VPClientRegistrationProvider extends AbstractClientRegistrationProvider {

    private static final Logger LOGGER = Logger.getLogger(OID4VPClientRegistrationProvider.class);

    public static final String VC_CLAIMS_PREFIX = "vc_";
    public static final String VC_TYPES_PREFIX = "vctypes_";

    public OID4VPClientRegistrationProvider(KeycloakSession session) {
        super(session);
    }

    // CUD implementations for the SIOP-2 client

    @POST
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response createOID4VCClient(OID4VPClient client) {
        LOGGER.infof("Create siop client %s", client);
        ClientRepresentation clientRepresentation = toClientRepresentation(client);
        validate(clientRepresentation);

        ClientRepresentation cr = create(
                new OID4VPClientRegistrationContext(session, clientRepresentation, this));
        URI uri = session.getContext().getUri().getAbsolutePathBuilder().path(cr.getClientId()).build();
        return Response.created(uri).entity(cr).build();
    }

    @PUT
    @Path("{clientId}")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response updateOID4VCClient(@PathParam("clientId") String clientDid, OID4VPClient client) {
        client.setClientDid(clientDid);
        ClientRepresentation clientRepresentation = toClientRepresentation(client);
        validate(clientRepresentation);
        clientRepresentation = update(clientDid,
                new OID4VPClientRegistrationContext(session, clientRepresentation, this));
        return Response.ok(clientRepresentation).build();
    }

    @DELETE
    @Path("{clientId}")
    public Response deleteOID4VCClient(@PathParam("clientId") String clientDid) {
        delete(clientDid);
        return Response.noContent().build();
    }

    /**
     * Validates the clientrepresentation to fulfill the requirement of a OID4VP client
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
     * Translate an incoming {@link OID4VPClient} into a keycloak native {@link ClientRepresentation}.
     *
     * @param OID4VPClient pojo, containing the SIOP-2 client parameters
     * @return a clientrepresentation, fitting keycloaks internal model
     */
    protected static ClientRepresentation toClientRepresentation(OID4VPClient OID4VPClient) {
        ClientRepresentation clientRepresentation = new ClientRepresentation();
        // protocol needs to be SIOP-2
        clientRepresentation.setProtocol(OID4VPClientRegistrationProviderFactory.PROTOCOL_ID);
        // id and clientId cannot be equal since did's might be to long, already validated to be non-null
        clientRepresentation.setId(UUID.randomUUID().toString());
        clientRepresentation.setClientId(OID4VPClient.getClientDid());
        // only add non-null parameters
        Optional.ofNullable(OID4VPClient.getDescription()).ifPresent(clientRepresentation::setDescription);
        Optional.ofNullable(OID4VPClient.getName()).ifPresent(clientRepresentation::setName);

        // add potential additional claims
        Map<String, String> clientAttributes = new HashMap<>(
                prefixClaims(VC_CLAIMS_PREFIX, OID4VPClient.getAdditionalClaims()));

        // only set supported VCs if present
        if (OID4VPClient.getSupportedVCTypes() != null) {
            OID4VPClient.getSupportedVCTypes()
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
