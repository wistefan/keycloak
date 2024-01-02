package org.keycloak.protocol.oid4vc.issuance.signing;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.keycloak.crypto.HashProvider;
import org.keycloak.crypto.JavaAlgorithm;
import org.keycloak.crypto.JavaAlgorithmHashProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.protocol.oid4vc.model.CredentialSubject;
import org.keycloak.protocol.oid4vc.model.VerifiableCredential;
import org.keycloak.protocol.oid4vc.model.sd_jwt_vc.*;
import org.keycloak.representations.JsonWebToken;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.time.Clock;
import java.util.*;

/**
 * {@link VerifiableCredentialsSigningService} implementing the SD_JWT_VC format. It returns a String, containing
 * the signed SD-JWT
 *
 * {@see https://drafts.oauth.net/oauth-sd-jwt-vc/draft-ietf-oauth-sd-jwt-vc.html}
 * {@see https://www.ietf.org/archive/id/draft-fett-oauth-selective-disclosure-jwt-02.html}
 *
 * @author <a href="https://github.com/wistefan">Stefan Wiedemann</a>
 */
public class SdJwtSigningService extends JwtSigningService {


    public static final String PROVIDER_ID = "sd-jwt-signing";
    private final ObjectMapper objectMapper;
    private final HashProvider hashProvider;
    private final int decoys;

    /**
     * According to {@see https://datatracker.ietf.org/doc/html/draft-ietf-oauth-selective-disclosure-jwt-05#name-conventions-and-terminology}
     * every base64 encoding is URL-Safe without padding.
     */
    private static final Base64.Encoder BASE_64_ENCODER = Base64.getUrlEncoder().withoutPadding();

    // TODO: cryptographic key binding is not yet implemented(@see https://www.ietf.org/archive/id/draft-terbu-oauth-sd-jwt-vc-00.html#section-4.2.2.2-3.5.1}.
    // should be added

    public SdJwtSigningService(KeycloakSession keycloakSession, String keyId, Clock clock, String algorithmType, ObjectMapper objectMapper, int decoys) {
        super(keycloakSession, keyId, clock, algorithmType);
        this.objectMapper = objectMapper;
        // make configurable
        this.hashProvider = new JavaAlgorithmHashProvider(JavaAlgorithm.SHA256);
        this.decoys = decoys;
    }

    @Override
    public String signCredential(VerifiableCredential verifiableCredential) {

        SdCredential sdCredential = toSdCredential(verifiableCredential);

        List<SdClaim> arrayClaims = new ArrayList<>();
        List<SdClaim> nonArrayClaims = new ArrayList<>();

        sdCredential.getSdClaims().forEach(sdc -> {
            if (sdc.getValue() instanceof List<?>) {
                arrayClaims.add(sdc);
            } else {
                nonArrayClaims.add(sdc);
            }
        });

        List<DisclosureClaim> disclosureClaims = nonArrayClaims.stream()
                .map(this::createNonArrayDisclosure)
                .toList();
        List<ArrayDisclosureClaim> arrayDisclosureClaims = arrayClaims.stream()
                .map(this::createArrayDisclosure)
                .toList();

        // create a mutable list
        List<String> digestList = new ArrayList<>(disclosureClaims.stream().map(DisclosureClaim::getDigest).toList());

        for (int i = 0; i < decoys; i++) {
            digestList.add(generateDecoy());
        }

        JsonWebToken jsonWebToken = new JsonWebToken();
        Optional.ofNullable(verifiableCredential.getExpirationDate()).ifPresent(d -> jsonWebToken.exp(d.getTime()));
        var subjectId = Optional.ofNullable(verifiableCredential.getId());
        if (subjectId.isEmpty()) {
            Object idObject = Optional.ofNullable(verifiableCredential.getAdditionalProperties().get("id"));
            if (idObject instanceof URI uriId) {
                subjectId = Optional.of(uriId);
            } else if (idObject instanceof String stringId) {
                subjectId = Optional.of(URI.create(stringId));
            }
        }
        subjectId.ifPresent(id -> jsonWebToken.subject(id.toString()));
        jsonWebToken.issuer(verifiableCredential.getIssuer().toString());
        jsonWebToken.nbf(clock.instant().getEpochSecond());
        jsonWebToken.iat(clock.instant().getEpochSecond());
        if (verifiableCredential.getType() == null || verifiableCredential.getType().size() != 1) {
            throw new SigningServiceException("SD-JWT only supports single type credentials.");
        }
        jsonWebToken.setOtherClaims("vct", verifiableCredential.getType().get(0));
        jsonWebToken.setOtherClaims("_sd_alg", JavaAlgorithm.SHA256.toLowerCase());
        jsonWebToken.setOtherClaims("_sd", digestList);
        arrayDisclosureClaims.forEach(adc -> {
            jsonWebToken.setOtherClaims(
                    adc.getKey(),
                    adc.getValues().stream()
                            .map(ArrayElement::asDigest)
                            .toList());
        });

        StringJoiner tokenJoiner = new StringJoiner(".");
        tokenJoiner.add(signToken(jsonWebToken, "vc+sd-jwt"));
        disclosureClaims.forEach(dc -> tokenJoiner.add(dc.getDisclosure()));
        arrayDisclosureClaims.stream().flatMap(adc -> adc.getValues().stream()).forEach(ae -> tokenJoiner.add(ae.getDisclosure()));
        return tokenJoiner.toString();
    }


    private SdCredential toSdCredential(VerifiableCredential verifiableCredential) {
        SdCredential sdCredential = new SdCredential();
        // first the known properties
        if (verifiableCredential.getContext() != null) {
            sdCredential.addSdClaim(new SdClaim("@context", verifiableCredential.getContext()));
        }
        if (verifiableCredential.getId() != null) {
            sdCredential.addSdClaim(new SdClaim("id", verifiableCredential.getId()));
        }
        verifiableCredential.getAdditionalProperties()
                .forEach((key, value) -> sdCredential.addSdClaim(new SdClaim(key, value)));
        CredentialSubject subject = verifiableCredential.getCredentialSubject();
        subject.getClaims().forEach((key, value) -> sdCredential.addSdClaim(new SdClaim(key, value)));
        return sdCredential;
    }

    private DisclosureClaim createNonArrayDisclosure(SdClaim claim) {
        try {
            String encodedArray = objectMapper.writeValueAsString(List.of(claim.getSalt(), claim.getKey(), claim.getValue()));
            String disclosure = createDisclosureString(encodedArray);
            return new DisclosureClaim(createDigest(disclosure), disclosure, claim.getSalt(), claim.getKey());

        } catch (JsonProcessingException e) {
            throw new SigningServiceException("Was not able to serialize the SD-Claim.", e);
        }
    }

    private ArrayDisclosureClaim createArrayDisclosure(SdClaim claim) {
        if (claim.getValue() instanceof List<?> listClaim) {
            ArrayDisclosureClaim arrayDisclosureClaim = new ArrayDisclosureClaim(claim.getKey());
            for (Object listEntry : listClaim) {
                try {
                    ArrayElement arrayElement = new ArrayElement(generateSalt(), listEntry);
                    String encodedElement = objectMapper.writeValueAsString(List.of(arrayElement.getSalt(), arrayElement.getValue()));
                    String elementDisclosure = createDisclosureString(encodedElement);
                    String digest = createDigest(elementDisclosure);
                    arrayElement.setDisclosure(elementDisclosure);
                    arrayElement.setDigest(digest);
                    arrayDisclosureClaim.addValue(arrayElement);
                } catch (JsonProcessingException e) {
                    throw new SigningServiceException("Was not able to serialize the list entry.", e);
                }
            }
            return arrayDisclosureClaim;
        } else {
            throw new SigningServiceException("Array-disclosures can only be built for list values.");
        }
    }

    private String createDisclosureString(String encodedEntry) {
        return BASE_64_ENCODER
                .encodeToString(encodedEntry.getBytes(StandardCharsets.UTF_8));
    }

    private String createDigest(String toDigest) {
        return BASE_64_ENCODER
                .encodeToString(
                        hashProvider.hash(toDigest.getBytes(StandardCharsets.UTF_8)));
    }

    private String generateDecoy() {
        return createDigest(generateSalt());
    }

    public static String generateSalt() {
        SecureRandom secureRandom = new SecureRandom();
        byte[] randomBytes = new byte[16]; // 128 bits are converted to 16 bytes;
        secureRandom.nextBytes(randomBytes);
        return BASE_64_ENCODER.encodeToString(randomBytes);
    }
}
