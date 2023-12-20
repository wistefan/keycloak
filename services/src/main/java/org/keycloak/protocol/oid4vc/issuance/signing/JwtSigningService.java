package org.keycloak.protocol.oid4vc.issuance.signing;


import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.jboss.logging.Logger;
import org.keycloak.crypto.*;
import org.keycloak.jose.jws.JWSBuilder;
import org.keycloak.models.KeycloakSession;
import org.keycloak.protocol.oid4vc.issuance.signing.jwt_vc.EdDSASignatureSignerContext;
import org.keycloak.protocol.oid4vc.model.VerifiableCredential;
import org.keycloak.representations.JsonWebToken;

import java.io.IOException;
import java.io.StringReader;
import java.net.URI;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.time.Clock;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import static org.keycloak.protocol.oid4vc.issuance.signing.jwt_vc.EdDSASignatureSignerContext.ED_25519;

/**
 * {@link VerifiableCredentialsSigningService} implementing the JWT_VC format. It returns a string, containing the
 * Signed JWT-Credential
 * {@see https://identity.foundation/jwt-vc-presentation-profile/}
 *
 * @author <a href="https://github.com/wistefan">Stefan Wiedemann</a>
 */
public class JwtSigningService extends SigningService<String> {


    public static final String PROVIDER_ID = "jwt-signing";
    private static final String ID_TEMPLATE = "urn:uuid:%s";

    private final SignatureSignerContext signatureSignerContext;

    public JwtSigningService(KeycloakSession keycloakSession, String keyId, Clock clock, String algorithmType) {
        super(keycloakSession, keyId, clock, algorithmType);
        var signingKey = getKey(keyId, algorithmType);
        signatureSignerContext = switch (algorithmType) {
            case ED_25519 -> new EdDSASignatureSignerContext(signingKey);
            case Algorithm.RS256, Algorithm.RS384, Algorithm.RS512, Algorithm.PS256, Algorithm.PS384, Algorithm.PS512 ->
                    new AsymmetricSignatureSignerContext(signingKey);
            case Algorithm.ES256, Algorithm.ES384, Algorithm.ES512 -> new ECDSASignatureSignerContext(signingKey);
            default ->
                    throw new SigningServiceException(String.format("Algorithm %s is not supported by the JWTSigningService.", algorithmType));
        };
    }

    @Override
    public String signCredential(VerifiableCredential verifiableCredential) {
        JsonWebToken jsonWebToken = new JsonWebToken();
        Optional.ofNullable(verifiableCredential.getExpirationDate()).ifPresent(d -> jsonWebToken.exp(d.getTime()));
        jsonWebToken.issuer(verifiableCredential.getIssuer().toString());
        jsonWebToken.nbf(clock.instant().getEpochSecond());
        jsonWebToken.iat(clock.instant().getEpochSecond());
        var credentialId = Optional.ofNullable(verifiableCredential.getId()).orElse(URI.create(String.format(ID_TEMPLATE, UUID.randomUUID())));
        jsonWebToken.id(credentialId.toString());

        jsonWebToken.subject(verifiableCredential.getCredentialSubject().getId());
        jsonWebToken.setOtherClaims("vc", verifiableCredential);
        return signToken(jsonWebToken, "JWT");
    }

    protected String signToken(JsonWebToken jsonWebToken, String type) {
        JWSBuilder jwsBuilder = new JWSBuilder();
        jwsBuilder.kid(keyId);
        jwsBuilder.type(type);
        return jwsBuilder.jsonContent(jsonWebToken).sign(signatureSignerContext);
    }

}