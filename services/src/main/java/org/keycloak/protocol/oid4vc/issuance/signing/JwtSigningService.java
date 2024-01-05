package org.keycloak.protocol.oid4vc.issuance.signing;


import org.jboss.logging.Logger;
import org.keycloak.crypto.Algorithm;
import org.keycloak.crypto.AsymmetricSignatureSignerContext;
import org.keycloak.crypto.ECDSASignatureSignerContext;
import org.keycloak.crypto.SignatureSignerContext;
import org.keycloak.jose.jws.JWSBuilder;
import org.keycloak.models.KeycloakSession;
import org.keycloak.protocol.oid4vc.model.VerifiableCredential;
import org.keycloak.representations.JsonWebToken;

import java.net.URI;
import java.time.Clock;
import java.util.Optional;
import java.util.UUID;

/**
 * {@link VerifiableCredentialsSigningService} implementing the JWT_VC format. It returns a string, containing the
 * Signed JWT-Credential
 * {@see https://identity.foundation/jwt-vc-presentation-profile/}
 *
 * @author <a href="https://github.com/wistefan">Stefan Wiedemann</a>
 */
public class JwtSigningService extends SigningService<String> {

    private static final Logger LOGGER = Logger.getLogger(JwtSigningService.class);

    private static final String ID_TEMPLATE = "urn:uuid:%s";

    private final SignatureSignerContext signatureSignerContext;
    protected final String issuerDid;

    public JwtSigningService(KeycloakSession keycloakSession, String keyId, Clock clock, String algorithmType, String issuerDid) {
        super(keycloakSession, keyId, clock, algorithmType);
        this.issuerDid = issuerDid;
        var signingKey = getKey(keyId, algorithmType);
        if (signingKey == null) {
            throw new SigningServiceException(String.format("No key for id  %s available.", keyId));
        }
        signatureSignerContext = switch (algorithmType) {
            case Algorithm.RS256, Algorithm.RS384, Algorithm.RS512, Algorithm.PS256, Algorithm.PS384, Algorithm.PS512 ->
                    new AsymmetricSignatureSignerContext(signingKey);
            case Algorithm.ES256, Algorithm.ES384, Algorithm.ES512 -> new ECDSASignatureSignerContext(signingKey);
            default ->
                    throw new SigningServiceException(String.format("Algorithm %s is not supported by the JWTSigningService.", algorithmType));
        };
        LOGGER.debug("Successfully initiated the JWT Signing Service.");
    }

    @Override
    public String signCredential(VerifiableCredential verifiableCredential) {
        JsonWebToken jsonWebToken = new JsonWebToken();

        Optional.ofNullable(verifiableCredential.getExpirationDate()).ifPresent(d -> jsonWebToken.exp(d.toInstant().getEpochSecond()));

        jsonWebToken.issuer(verifiableCredential.getIssuer().toString());
        jsonWebToken.nbf(clock.instant().getEpochSecond());
        jsonWebToken.iat(clock.instant().getEpochSecond());
        var credentialId = Optional.ofNullable(verifiableCredential.getId()).orElse(URI.create(String.format(ID_TEMPLATE, UUID.randomUUID())));
        jsonWebToken.id(credentialId.toString());
        Optional.ofNullable(verifiableCredential.getCredentialSubject().getClaims().get("id"))
                .map(Object::toString)
                .ifPresent(jsonWebToken::subject);

        jsonWebToken.setOtherClaims("vc", verifiableCredential);

        return signToken(jsonWebToken, "JWT");
    }

    protected String signToken(JsonWebToken jsonWebToken, String type) {

        return new JWSBuilder()
                .type(type)
                .jsonContent(jsonWebToken).sign(signatureSignerContext);
    }

}