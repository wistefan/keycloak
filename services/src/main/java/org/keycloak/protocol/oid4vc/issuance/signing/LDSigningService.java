package org.keycloak.protocol.oid4vc.issuance.signing;


import com.fasterxml.jackson.databind.ObjectMapper;
import org.jboss.logging.Logger;
import org.keycloak.common.util.Base64;
import org.keycloak.protocol.oid4vc.issuance.signing.vcdm.Ed255192018Suite;
import org.keycloak.protocol.oid4vc.issuance.signing.vcdm.RsaSignature2018Suite;
import org.keycloak.protocol.oid4vc.issuance.signing.vcdm.SecuritySuite;
import org.keycloak.protocol.oid4vc.model.vcdm.LdProof;
import org.keycloak.protocol.oid4vc.model.VerifiableCredential;

import java.io.IOException;
import java.time.Clock;
import java.util.Date;

public class LDSigningService extends SigningService<VerifiableCredential> {

    public static final String PROVIDER_ID = "ldp-signing";
    private static final Logger LOGGER = Logger.getLogger(LDSigningService.class);

    private SecuritySuite securitySuite;
    private ObjectMapper objectMapper;

    public LDSigningService(KeyLoader keyLoader, String keyId,
                            Clock clock, String ldpType, ObjectMapper objectMapper) {
        super(keyLoader, keyId, clock, ldpType);
        this.objectMapper = objectMapper;

        securitySuite = switch (ldpType) {
            case Ed255192018Suite.PROOF_TYPE -> new Ed255192018Suite(objectMapper);
            case RsaSignature2018Suite.PROOF_TYPE -> new RsaSignature2018Suite();
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
        byte[] signature = securitySuite.sign(hashedData, keyLoader.loadKey());
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
