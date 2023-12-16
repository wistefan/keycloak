package org.keycloak.sdjwt;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPrivateKeySpec;
import java.security.spec.ECPublicKeySpec;
import java.util.HashMap;
import java.util.Map;

import org.keycloak.common.util.Base64Url;
import org.keycloak.common.util.KeyUtils;
import org.keycloak.crypto.AsymmetricSignatureSignerContext;
import org.keycloak.crypto.KeyUse;
import org.keycloak.crypto.KeyWrapper;
import org.keycloak.crypto.SignatureSignerContext;

import com.fasterxml.jackson.databind.JsonNode;

/**
 * Import test-settings from:
 * https://github.com/openwallet-foundation-labs/sd-jwt-python/blob/main/src/sd_jwt/utils/demo_settings.yml
 * 
 * @author <a href="mailto:francis.pouatcha@adorsys.com">Francis Pouatcha</a>
 */
public class TestSettings {
    public final SignatureSignerContext holderSigContext;
    public final SignatureSignerContext issuerSigContext;

    private static TestSettings instance = null;

    public static TestSettings getInstance() {
        if (instance == null) {
            instance = new TestSettings();
        }
        return instance;
    }

    public SignatureSignerContext getIssuerSignerContext() {
        return issuerSigContext;
    }

    public SignatureSignerContext getHolderSignerContext() {
        return holderSigContext;
    }

    // private constructor
    private TestSettings() {
        JsonNode testSettings = TestUtils.readClaimSet(getClass(), "sdjwt/test-settings.json");
        JsonNode keySettings = testSettings.get("key_settings");

        holderSigContext = initSigContext(keySettings, "holder_key", "ES256", "holder");
        issuerSigContext = initSigContext(keySettings, "issuer_key", "ES256", "doc-signer-05-25-2022");
    }

    private static SignatureSignerContext initSigContext(JsonNode keySettings, String keyName, String algorithm,
            String kid) {
        JsonNode keySetting = keySettings.get(keyName);
        KeyPair keyPair = readKeyPair(keySetting);
        return getSignatureSignerContext(keyPair, algorithm, kid);
    }

    private static KeyPair readKeyPair(JsonNode keySetting) {
        String curveName = keySetting.get("crv").asText();
        String base64UrlEncodedD = keySetting.get("d").asText();
        String base64UrlEncodedX = keySetting.get("x").asText();
        String base64UrlEncodedY = keySetting.get("y").asText();
        return readEcdsaKeyPair(curveName, base64UrlEncodedD, base64UrlEncodedX, base64UrlEncodedY);
    }

    private static KeyPair readEcdsaKeyPair(String curveName, String base64UrlEncodedD, String base64UrlEncodedX,
            String base64UrlEncodedY) {

        ECParameterSpec ecSpec = getECParameterSpec(ECDSA_CURVE_2_SPECS_NAMES.get(curveName));

        byte[] dBytes = Base64Url.decode(base64UrlEncodedD);
        byte[] xBytes = Base64Url.decode(base64UrlEncodedX);
        byte[] yBytes = Base64Url.decode(base64UrlEncodedY);

        try {
            KeyFactory keyFactory = KeyFactory.getInstance("EC");

            // Generate ECPrivateKey
            BigInteger dValue = new BigInteger(1, dBytes);
            PrivateKey privateKey = keyFactory.generatePrivate(new ECPrivateKeySpec(dValue, ecSpec));

            // Instantiate ECPoint
            BigInteger xValue = new BigInteger(1, xBytes);
            BigInteger yValue = new BigInteger(1, yBytes);
            ECPoint point = new ECPoint(xValue, yValue);

            // Generate ECPublicKey
            PublicKey publicKey = keyFactory.generatePublic(new ECPublicKeySpec(point, ecSpec));
            return new KeyPair(publicKey, privateKey);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private static final Map<String, ECParameterSpec> ECDSA_KEY_SPECS = new HashMap<>();

    private static ECParameterSpec getECParameterSpec(String paramSpecName) {
        return ECDSA_KEY_SPECS.computeIfAbsent(paramSpecName, TestSettings::generateEcdsaKeySpec);
    }

    // generate key spec
    private static ECParameterSpec generateEcdsaKeySpec(String paramSpecName) {
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC");
            ECGenParameterSpec ecGenParameterSpec = new ECGenParameterSpec(paramSpecName);
            keyPairGenerator.initialize(ecGenParameterSpec);
            KeyPair keyPair = keyPairGenerator.generateKeyPair();
            return ((java.security.interfaces.ECPublicKey) keyPair.getPublic()).getParams();
        } catch (Exception e) {
            throw new RuntimeException("Error obtaining ECParameterSpec for P-256 curve", e);
        }
    }

    private static SignatureSignerContext getSignatureSignerContext(KeyPair keyPair, String algorithm, String kid) {
        KeyWrapper keyWrapper = new KeyWrapper();
        keyWrapper.setKid(KeyUtils.createKeyId(keyPair.getPublic()));
        keyWrapper.setAlgorithm(algorithm);
        keyWrapper.setPrivateKey(keyPair.getPrivate());
        keyWrapper.setPublicKey(keyPair.getPublic());
        keyWrapper.setType(keyPair.getPublic().getAlgorithm());
        keyWrapper.setUse(KeyUse.SIG);
        keyWrapper.setKid(kid);
        return new AsymmetricSignatureSignerContext(keyWrapper);
    }

    private static final Map<String, String> ECDSA_CURVE_2_SPECS_NAMES = new HashMap<>();

    private static final void curveToSpecName() {
        ECDSA_CURVE_2_SPECS_NAMES.put("P-256", "secp256r1");
    }

    static {
        curveToSpecName();
    }
}
