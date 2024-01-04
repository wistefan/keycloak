package org.keycloak.protocol.oid4vc.issuance.signing.vcdm;

import com.apicatalog.jsonld.JsonLd;
import com.apicatalog.jsonld.JsonLdError;
import com.apicatalog.jsonld.document.JsonDocument;
import com.apicatalog.jsonld.http.DefaultHttpClient;
import com.apicatalog.jsonld.http.media.MediaType;
import com.apicatalog.jsonld.json.JsonUtils;
import com.apicatalog.jsonld.loader.HttpLoader;
import com.apicatalog.rdf.Rdf;
import com.apicatalog.rdf.RdfDataset;
import com.apicatalog.rdf.io.RdfWriter;
import com.apicatalog.rdf.io.error.RdfWriterException;
import com.apicatalog.rdf.io.error.UnsupportedContentException;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.setl.rdf.normalization.RdfNormalize;
import jakarta.json.JsonObject;
import jakarta.json.JsonValue;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.signers.Ed25519Signer;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.keycloak.protocol.oid4vc.issuance.signing.SigningServiceException;
import org.keycloak.protocol.oid4vc.model.VerifiableCredential;

import java.io.IOException;
import java.io.StringReader;
import java.io.StringWriter;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.util.Optional;

/**
 * Implementation of a LD-Crypto Suite for Ed25519Signature2018
 * {@see https://w3c-ccg.github.io/ld-cryptosuite-registry/#ed25519signature2018}
 *
 * @author <a href="https://github.com/wistefan">Stefan Wiedemann</a>
 */
public class Ed255192018Suite implements SecuritySuite {

    private final ObjectMapper objectMapper;

    private static final String CANONICALIZATION_ALGORITHM = "https://w3id.org/security#URDNA2015";
    private static final String DIGEST_ALGORITHM = "http://w3id.org/digests#sha256";
    private static final String SIGNATURE_ALGORITHM = "http://w3id.org/security#ed25519";

    public static final String PROOF_TYPE = "Ed25519Signature2018";

    public Ed255192018Suite(ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
    }

    @Override
    public byte[] transform(VerifiableCredential verifiableCredential) {

        try {
            String credentialString = objectMapper.writeValueAsString(verifiableCredential);

            var credentialDocument = JsonDocument.of(new StringReader(credentialString));

            var expandedDocument = JsonLd.expand(credentialDocument)
                    .loader(new HttpLoader(DefaultHttpClient.defaultInstance()))
                    .get();
            Optional<JsonObject> documentObject = Optional.empty();
            if (JsonUtils.isArray(expandedDocument)) {
                documentObject = expandedDocument.asJsonArray().stream().filter(JsonUtils::isObject).map(JsonValue::asJsonObject).findFirst();
            } else if (JsonUtils.isObject(expandedDocument)) {
                documentObject = Optional.of(expandedDocument.asJsonObject());
            }
            if (documentObject.isPresent()) {

                RdfDataset rdfDataset = JsonLd.toRdf(JsonDocument.of(documentObject.get())).get();
                RdfDataset canonicalDataset = RdfNormalize.normalize(rdfDataset);

                StringWriter writer = new StringWriter();
                RdfWriter rdfWriter = Rdf.createWriter(MediaType.N_QUADS, writer);
                rdfWriter.write(canonicalDataset);

                return writer.toString()
                        .getBytes(StandardCharsets.UTF_8);
            } else {
                throw new SigningServiceException("Was not able to get the expanded json.");
            }
        } catch (JsonProcessingException e) {
            throw new SigningServiceException("Was not able to serialize the credential", e);
        } catch (JsonLdError e) {
            throw new SigningServiceException("Was not able to create a JsonLD Document from the serialized string.", e);
        } catch (UnsupportedContentException | IOException | RdfWriterException e) {
            throw new SigningServiceException("Was not able to canonicalize the json-ld.", e);
        }

    }

    @Override
    public byte[] digest(byte[] transformedData) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            return md.digest(transformedData);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public byte[] sign(byte[] hashData, PrivateKey key) {
        Ed25519Signer signer = new Ed25519Signer();
        signer.init(true, toKeyParameter(key));
        signer.update(hashData, 0, hashData.length);
        return signer.generateSignature();
    }


    private static AsymmetricKeyParameter toKeyParameter(PrivateKey key) {
        try {
            return PrivateKeyFactory.createKey(key.getEncoded());
        } catch (IOException e) {
            throw new SigningServiceException("Was not able to get the private key parameter.", e);
        }

    }

    @Override
    public String getProofType() {
        return PROOF_TYPE;
    }
}
