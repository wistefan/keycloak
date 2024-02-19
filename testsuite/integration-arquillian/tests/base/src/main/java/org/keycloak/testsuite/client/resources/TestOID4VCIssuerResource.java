package org.keycloak.testsuite.client.resources;


import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.core.Response;
import org.keycloak.protocol.oid4vc.model.CredentialRequest;
import org.keycloak.utils.MediaType;

@Path("/protocol/oid4vc")
public interface TestOID4VCIssuerResource {

    @GET
    @Produces(MediaType.APPLICATION_JSON)
    @Path("/credential-offer-uri")
    Response getCredentialOfferURI(@QueryParam("credentialId") String vcId);

    @GET
    @Produces(MediaType.APPLICATION_JSON)
    @Path("/credential-offer/{nonce}")
    Response getCredentialOffer(@PathParam("nonce") String nonce);

    @POST
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    @Path("/credential")
    Response requestCredential(CredentialRequest credentialRequestVO);

}
