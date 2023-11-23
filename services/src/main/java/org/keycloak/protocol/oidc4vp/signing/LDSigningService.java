package org.keycloak.protocol.oidc4vp.signing;

import com.danubetech.keyformats.crypto.ByteSigner;
import com.danubetech.keyformats.crypto.impl.Ed25519_EdDSA_PrivateKeySigner;
import com.danubetech.keyformats.crypto.impl.RSA_PS256_PrivateKeySigner;
import com.danubetech.keyformats.crypto.impl.RSA_RS256_PrivateKeySigner;
import com.danubetech.verifiablecredentials.VerifiableCredential;
import foundation.identity.jsonld.JsonLDException;
import info.weboftrust.ldsignatures.LdProof;
import info.weboftrust.ldsignatures.jsonld.LDSecurityKeywords;
import info.weboftrust.ldsignatures.signer.EcdsaSecp256k1Signature2019LdSigner;
import info.weboftrust.ldsignatures.signer.Ed25519Signature2018LdSigner;
import info.weboftrust.ldsignatures.signer.Ed25519Signature2020LdSigner;
import info.weboftrust.ldsignatures.signer.JcsEd25519Signature2020LdSigner;
import info.weboftrust.ldsignatures.signer.JsonWebSignature2020LdSigner;
import info.weboftrust.ldsignatures.signer.LdSigner;
import info.weboftrust.ldsignatures.signer.RsaSignature2018LdSigner;
import info.weboftrust.ldsignatures.suites.EcdsaSecp256k1Signature2019SignatureSuite;
import info.weboftrust.ldsignatures.suites.Ed25519Signature2018SignatureSuite;
import info.weboftrust.ldsignatures.suites.Ed25519Signature2020SignatureSuite;
import info.weboftrust.ldsignatures.suites.JcsEd25519Signature2020SignatureSuite;
import info.weboftrust.ldsignatures.suites.JsonWebSignature2020SignatureSuite;
import info.weboftrust.ldsignatures.suites.RsaSignature2018SignatureSuite;
import org.bitcoinj.core.ECKey;
import org.jboss.logging.Logger;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.time.Clock;
import java.util.Date;
import java.util.Optional;

public class LDSigningService extends SigningService<VerifiableCredential> {
	private static final Logger LOGGER = Logger.getLogger(LDSigningService.class);

	private final Clock clock;

	public LDSigningService(String keyPath, Optional<String> keyId,
			Clock clock) {
		super(keyPath, keyId);
		this.clock = clock;
	}

	@Override
	public VerifiableCredential signCredential(VerifiableCredential verifiableCredential) {
		LOGGER.debug("Sign credential with an ld-proof.");
		String proofType = Optional.ofNullable(verifiableCredential.getLdProof()).map(LdProof::getType)
				// use a default
				.orElse(LDSignatureType.RSA_SIGNATURE_2018.getValue());
		LDSignatureType signatureType = LDSignatureType.getByValue(proofType);
		AlgorithmType algorithmType = AlgorithmType.getByValue(signingKey.getPrivate().getAlgorithm());
		var ldSigner = switch (signatureType) {
			case RSA_SIGNATURE_2018 -> getRsaSigner(algorithmType);
			case ED_25519_SIGNATURE_2018 -> getEd25519Signature2018Signer(algorithmType);
			case ED_25519_SIGNATURE_2020 -> getEd25519Signature2020Signer(algorithmType);
			case ECDSA_SECP_256K1_SIGNATURE_2019 -> getEcdsaSecp256k1Signature2019Signer(algorithmType);
			case JSON_WEB_SIGNATURE_2020 -> getJsonWebSignature2020Signer(algorithmType);
			case JCS_ED_25519_SIGNATURE_2020 -> getJcsEd25519Signature2020Signer(algorithmType);
		};
		ldSigner.setProofPurpose(LDSecurityKeywords.JSONLD_TERM_ASSERTIONMETHOD);
		ldSigner.setCreated(Date.from(clock.instant()));
		try {
			ldSigner.sign(verifiableCredential);
		} catch (IOException | GeneralSecurityException | JsonLDException e) {
			throw new SigningServiceException("Was not able to sign the credential.", e);
		}
		return verifiableCredential;
	}

	private LdSigner<JcsEd25519Signature2020SignatureSuite> getJcsEd25519Signature2020Signer(AlgorithmType algorithmType) {
		if (algorithmType != AlgorithmType.ED_DSA_ED25519) {
			throw new IllegalArgumentException("Signing key does not support JCS_ED_25519_SIGNATURE_2020.");
		}
		return new JcsEd25519Signature2020LdSigner(signingKey.getPrivate().getEncoded());
	}

	private LdSigner<JsonWebSignature2020SignatureSuite> getJsonWebSignature2020Signer(AlgorithmType algorithmType) {

		String concreteAlgorithm = signingKey.getPrivate().getAlgorithm();

		ByteSigner byteSigner = switch (algorithmType) {
			case RSA -> {
				if (concreteAlgorithm.equalsIgnoreCase("rs256")) {
					yield new RSA_RS256_PrivateKeySigner(signingKey);
				} else {
					yield new RSA_PS256_PrivateKeySigner(signingKey);
				}
			}
			case ECDSA_SECP256K1 -> getEcdsaSecp256k1Signature2019Signer(algorithmType).getSigner();
			case ED_DSA_ED25519 -> new Ed25519_EdDSA_PrivateKeySigner(signingKey.getPrivate().getEncoded());
		};
		return new JsonWebSignature2020LdSigner(byteSigner);
	}

	private LdSigner<EcdsaSecp256k1Signature2019SignatureSuite> getEcdsaSecp256k1Signature2019Signer(AlgorithmType algorithmType) {
		if (algorithmType != AlgorithmType.ECDSA_SECP256K1) {
			throw new IllegalArgumentException("Signing key does not support ECDSA_SECP_256K1_SIGNATURE_2019.");
		}
		return new EcdsaSecp256k1Signature2019LdSigner(ECKey.fromPrivate(signingKey.getPrivate().getEncoded()));
	}

	private LdSigner<Ed25519Signature2018SignatureSuite> getEd25519Signature2018Signer(AlgorithmType algorithmType) {
		if (algorithmType != AlgorithmType.ED_DSA_ED25519) {
			throw new IllegalArgumentException("Signing key does not support ED_25519_SIGNATURE_2018.");
		}
		return new Ed25519Signature2018LdSigner(signingKey.getPrivate().getEncoded());
	}

	private LdSigner<Ed25519Signature2020SignatureSuite> getEd25519Signature2020Signer(AlgorithmType algorithmType) {
		if (algorithmType != AlgorithmType.ED_DSA_ED25519) {
			throw new IllegalArgumentException("Signing key does not support ED_25519_SIGNATURE_2020.");
		}
		return new Ed25519Signature2020LdSigner(signingKey.getPrivate().getEncoded());
	}

	private LdSigner<RsaSignature2018SignatureSuite> getRsaSigner(AlgorithmType algorithmType) {
		if (algorithmType != AlgorithmType.RSA) {
			throw new IllegalArgumentException("Signing key does not support RSA_SIGNATURE_2018.");
		}
		return new RsaSignature2018LdSigner(signingKey);
	}

}
