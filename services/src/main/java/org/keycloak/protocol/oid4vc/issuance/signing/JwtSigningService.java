package org.keycloak.protocol.oid4vc.signing;


import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.keycloak.common.util.KeyUtils;
import org.keycloak.crypto.*;
import org.keycloak.jose.jws.JWSBuilder;
import org.keycloak.protocol.oid4vc.model.VerifiableCredential;
import org.keycloak.protocol.oid4vc.signing.jwt_vc.EdDSASignatureSignerContext;
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

import static org.keycloak.protocol.oid4vc.signing.jwt_vc.EdDSASignatureSignerContext.ED_25519;

public class JwtSigningService extends SigningService<String> {

    private static final String ID_TEMPLATE = "urn:uuid:%s";

    private SignatureSignerContext signatureSignerContext;

    public JwtSigningService(KeyLoader keyLoader, Optional<String> optionalKeyId, Clock clock, String algorithmType) {
        super(keyLoader, optionalKeyId, clock, algorithmType);

        var signingKey = getKeyWrapper(algorithmType);
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
        var credentialId = Optional.ofNullable(verifiableCredential.getAdditionalProperties().get("id")).orElse(String.format(ID_TEMPLATE, UUID.randomUUID()));
        if (credentialId instanceof String idString) {
            jsonWebToken.id(idString);
        } else if (credentialId instanceof URI idUri) {
            jsonWebToken.id(idUri.toString());
        } else {
            throw new SigningServiceException("The id needs to be a URI or a string.");
        }
        jsonWebToken.subject(verifiableCredential.getCredentialSubject().getId());
        jsonWebToken.setOtherClaims("vc", verifiableCredential);
        return signToken(jsonWebToken, type);
    }

    protected String signToken(JsonWebToken jsonWebToken, String type) {
        JWSBuilder jwsBuilder = new JWSBuilder();
        optionalKeyId.ifPresent(jwsBuilder::kid);
        jwsBuilder.type(type);
        return jwsBuilder.jsonContent(jsonWebToken).sign(signatureSignerContext);
    }

    private KeyWrapper getKeyWrapper(String algorithm) {
        KeyPair keyPair = parsePem(keyLoader.loadKey());

        KeyWrapper keyWrapper = new KeyWrapper();
        optionalKeyId.ifPresent(keyWrapper::setKid);

        keyWrapper.setAlgorithm(algorithm);
        keyWrapper.setPrivateKey(keyPair.getPrivate());

        if (keyPair.getPublic() != null) {
            keyWrapper.setPublicKey(keyPair.getPublic());
            keyWrapper.setKid(KeyUtils.createKeyId(keyPair.getPublic()));
            keyWrapper.setType(keyPair.getPublic().getAlgorithm());
        }
        keyWrapper.setUse(KeyUse.SIG);
        return keyWrapper;
    }

    protected KeyPair parsePem(String keyString) {
        PEMParser pemParser = new PEMParser(new StringReader(keyString));
        List<Object> parsedObjects = new ArrayList<>();
        try {
            var currentObject = pemParser.readObject();
            while (currentObject != null) {
                parsedObjects.add(currentObject);
                currentObject = pemParser.readObject();
            }
        } catch (IOException e) {
            throw new SigningServiceException("Was not able to parse the key-pem", e);
        }
        SubjectPublicKeyInfo publicKeyInfo = null;
        PrivateKeyInfo privateKeyInfo = null;
        for (Object parsedObject : parsedObjects) {
            if (parsedObject instanceof SubjectPublicKeyInfo spki) {
                publicKeyInfo = spki;
            } else if (parsedObject instanceof PrivateKeyInfo pki) {
                privateKeyInfo = pki;
            } else if (parsedObject instanceof PEMKeyPair pkp) {
                publicKeyInfo = pkp.getPublicKeyInfo();
                privateKeyInfo = pkp.getPrivateKeyInfo();
            }
        }
        if (privateKeyInfo == null) {
            throw new SigningServiceException("Was not able to read a private key.");
        }
        PublicKey publicKey = null;
        if (publicKeyInfo != null) {
            try {
                KeyFactory keyFactory = KeyFactory.getInstance(publicKeyInfo.getAlgorithm().getAlgorithm().getId());
                publicKey = keyFactory.generatePublic(new X509EncodedKeySpec(publicKeyInfo.getEncoded()));
            } catch (NoSuchAlgorithmException | InvalidKeySpecException | IOException e) {
                throw new SigningServiceException("Was not able to get the public key.", e);
            }
        }
        try {
            KeyFactory privateKeyFactory = KeyFactory.getInstance(
                    privateKeyInfo.getPrivateKeyAlgorithm().getAlgorithm().getId());
            PrivateKey privateKey = privateKeyFactory.generatePrivate(
                    new PKCS8EncodedKeySpec(privateKeyInfo.getEncoded()));
            return new KeyPair(publicKey, privateKey);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException | IOException e) {
            throw new SigningServiceException("Was not able to get the public key.", e);
        }
    }
}