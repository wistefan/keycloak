package org.keycloak.protocol.oid4vc.issuance.signing;


import com.fasterxml.jackson.databind.ObjectMapper;
import org.jboss.logging.Logger;
import org.keycloak.common.util.Base64;
import org.keycloak.models.KeycloakSession;
import org.keycloak.protocol.oid4vc.issuance.signing.vcdm.Ed255192018Suite;
import org.keycloak.protocol.oid4vc.issuance.signing.vcdm.SecuritySuite;
import org.keycloak.protocol.oid4vc.model.VerifiableCredential;
import org.keycloak.protocol.oid4vc.model.vcdm.LdProof;

import java.io.IOException;
import java.security.PrivateKey;
import java.time.Clock;
import java.util.Date;

/**
 * {@link VerifiableCredentialsSigningService} implementing the LDP_VC format. It returns a Verifiable Credential,
 * containing the created LDProof.
 * <p>
 * {@see https://www.w3.org/TR/vc-data-model/}
 *
 * @author <a href="https://github.com/wistefan">Stefan Wiedemann</a>
 */
public class LDSigningService extends SigningService<VerifiableCredential> {

    public static final String PROVIDER_ID = "ldp-signing";

    private SecuritySuite securitySuite;


    public LDSigningService(KeycloakSession keycloakSession, String keyId, Clock clock, String ldpType, ObjectMapper objectMapper) {
        super(keycloakSession, keyId, clock, ldpType);

        securitySuite = switch (ldpType) {
            case Ed255192018Suite.PROOF_TYPE -> new Ed255192018Suite(objectMapper);
            default -> throw new SigningServiceException(String.format("Proof Type %s is not supported.", ldpType));
        };

    }

    @Override
    public VerifiableCredential signCredential(VerifiableCredential verifiableCredential) {
        return addProof(verifiableCredential);
    }


    private VerifiableCredential addProof(VerifiableCredential verifiableCredential) {

        byte[] transformedData = securitySuite.transform(verifiableCredential);
        byte[] hashedData = securitySuite.digest(transformedData);
        byte[] signature = securitySuite.sign(hashedData, (PrivateKey) getKey(keyId, "Ed25519").getPrivateKey());
        LdProof ldProof = new LdProof();
        ldProof.setProofPurpose("assertionMethod");
        ldProof.setType(securitySuite.getProofType());
        ldProof.setCreated(Date.from(clock.instant()));
        ldProof.setVerificationMethod(keyId);

        try {
            var proofValue = Base64.encodeBytes(signature, Base64.URL_SAFE);
            ldProof.setProofValue(proofValue);
            verifiableCredential.setProof(ldProof);
            return verifiableCredential;
        } catch (IOException e) {
            throw new SigningServiceException("Was not able to encode the signature.", e);
        }
    }

}
