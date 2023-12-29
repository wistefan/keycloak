package org.keycloak.sdjwt;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import java.util.Optional;

import org.junit.Test;
import org.keycloak.crypto.SignatureSignerContext;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;

/**
 * @author <a href="mailto:francis.pouatcha@adorsys.com">Francis Pouatcha</a>
 */
public class SdJwtTest {
    // Additional tests can be written to cover edge cases, error conditions,
    // and any other functionality specific to the SdJwt class.
    @Test
    public void testIssuerSignedJWTWithUndiclosedClaims3_3() {
        DisclosureSpec disclosureSpec = DisclosureSpec.builder()
                .withUndisclosedClaim("given_name", "2GLC42sKQveCfGfryNRN9w")
                .withUndisclosedClaim("family_name", "eluV5Og3gSNII8EYnsxA_A")
                .withUndisclosedClaim("email", "6Ij7tM-a5iVPGboS5tmvVA")
                .withUndisclosedClaim("phone_number", "eI8ZWm9QnKPpNPeNenHdhQ")
                .withUndisclosedClaim("address", "Qg_O64zqAxe412a108iroA")
                .withUndisclosedClaim("birthdate", "AJx-095VPrpTtN4QMOqROA")
                .withUndisclosedClaim("is_over_18", "Pc33JM2LchcU_lHggv_ufQ")
                .withUndisclosedClaim("is_over_21", "G02NSrQfjFXQ7Io09syajA")
                .withUndisclosedClaim("is_over_65", "lklxF5jMYlGTPUovMNIvCA")
                .build();

        // Read claims provided by the holder
        JsonNode holderClaimSet = TestUtils.readClaimSet(getClass(), "sdjwt/s3.3-holder-claims.json");
        // Read claims added by the issuer
        JsonNode issuerClaimSet = TestUtils.readClaimSet(getClass(), "sdjwt/s3.3-issuer-claims.json");

        // Merge both
        ((ObjectNode) holderClaimSet).setAll((ObjectNode) issuerClaimSet);

        SdJwt sdJwt = new SdJwt(disclosureSpec, holderClaimSet, Optional.empty(),
                TestSettings.getInstance().getIssuerSignerContext());
        IssuerSignedJWT jwt = sdJwt.getIssuerSignedJWT();

        JsonNode expected = TestUtils.readClaimSet(getClass(), "sdjwt/s3.3-issuer-payload.json");
        assertEquals(expected, jwt.getPayload());

        String sdJwtString = sdJwt.toSdJwtString();

        SdJwt actualSdJwt = new SdJwt(sdJwtString);

        String expectedString = TestUtils.readFileAsString(getClass(), "sdjwt/s3.3-unsecured-sd-jwt.txt");
        SdJwt expecteSdJwt = new SdJwt(expectedString);

        TestCompareSdJwt.compare(expecteSdJwt, actualSdJwt);

    }

    @Test
    public void settingsTest() {
        SignatureSignerContext issuerSignerContext = TestSettings.getInstance().getIssuerSignerContext();
        assertNotNull(issuerSignerContext);
    }

    @Test
    public void testA1_Example2_with_nested_disclosure_and_decoy_claims() {
        DisclosureSpec addrDisclosureSpec = DisclosureSpec.builder()
                .withUndisclosedClaim("street_address", "AJx-095VPrpTtN4QMOqROA")
                .withUndisclosedClaim("locality", "Pc33JM2LchcU_lHggv_ufQ")
                .withUndisclosedClaim("region", "G02NSrQfjFXQ7Io09syajA")
                .withUndisclosedClaim("country", "lklxF5jMYlGTPUovMNIvCA")
                .withDecoyClaim("2GLC42sKQveCfGfryNRN9w")
                .withDecoyClaim("eluV5Og3gSNII8EYnsxA_A")
                .withDecoyClaim("6Ij7tM-a5iVPGboS5tmvVA")
                .withDecoyClaim("eI8ZWm9QnKPpNPeNenHdhQ")
                .build();

        DisclosureSpec disclosureSpec = DisclosureSpec.builder()
                .withUndisclosedClaim("sub", "2GLC42sKQveCfGfryNRN9w")
                .withUndisclosedClaim("given_name", "eluV5Og3gSNII8EYnsxA_A")
                .withUndisclosedClaim("family_name", "6Ij7tM-a5iVPGboS5tmvVA")
                .withUndisclosedClaim("email", "eI8ZWm9QnKPpNPeNenHdhQ")
                .withUndisclosedClaim("phone_number", "Qg_O64zqAxe412a108iroA")
                .withUndisclosedClaim("birthdate", "yytVbdAPGcgl2rI4C9GSog")
                .withDecoyClaim("AJx-095VPrpTtN4QMOqROA")
                .withDecoyClaim("G02NSrQfjFXQ7Io09syajA")
                .build();

        // Read claims provided by the holder
        JsonNode holderClaimSet = TestUtils.readClaimSet(getClass(), "sdjwt/a1.example2-holder-claims.json");

        // Read claims provided by the holder
        JsonNode addressClaimSet = holderClaimSet.get("address");
        SdJwt addrSdJWT = new SdJwt(addrDisclosureSpec, addressClaimSet, Optional.empty(), null);
        IssuerSignedJWT addrIssuerJWT = addrSdJWT.getIssuerSignedJWT();

        JsonNode addPayload = addrIssuerJWT.getPayload();
        ((ObjectNode) addPayload).remove(IssuerSignedJWT.CLAIM_NAME_SD_HASH_ALGORITHM);

        JsonNode expectedAddrPayload = TestUtils.readClaimSet(getClass(), "sdjwt/a1.example2-address-payload.json");
        assertEquals(expectedAddrPayload, addPayload);

        ((ObjectNode) holderClaimSet).set("address", addPayload);

        // Read claims added by the issuer
        JsonNode issuerClaimSet = TestUtils.readClaimSet(getClass(), "sdjwt/a1.example2-issuer-claims.json");

        // Merge both
        ((ObjectNode) holderClaimSet).setAll((ObjectNode) issuerClaimSet);

        SdJwt sdJwt = new SdJwt(disclosureSpec, holderClaimSet, Optional.empty(), null);
        IssuerSignedJWT jwt = sdJwt.getIssuerSignedJWT();

        JsonNode expected = TestUtils.readClaimSet(getClass(), "sdjwt/a1.example2-issuer-payload.json");
        assertEquals(expected, jwt.getPayload());
    }

}
