package org.keycloak.protocol.oid4vc;

import org.jboss.logging.Logger;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.keycloak.protocol.oid4vc.OIDC4VPClient;
import org.keycloak.protocol.oid4vc.OIDC4VPClientRegistrationProvider;
import org.keycloak.protocol.oid4vc.OIDC4VPClientRegistrationProviderFactory;
import org.keycloak.protocol.oid4vc.model.Format;
import org.keycloak.representations.idm.ClientRepresentation;
import org.keycloak.services.ErrorResponseException;

import java.lang.reflect.Field;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.fail;

public class OIDC4VPClientRegistrationProviderTest {

    private static final Logger LOGGER = Logger.getLogger(OIDC4VPClientRegistrationProviderTest.class);

    @DisplayName("Validate clientRepresentation to fit the requirements of a SIOP-2 client.")
    @ParameterizedTest
    @MethodSource("provideClientRepresentations")
    public void testValidate(ClientRepresentation toTest, ExpectedResult<Boolean> expectedResult) {
        try {
            OIDC4VPClientRegistrationProvider.validate(toTest);
        } catch (ErrorResponseException e) {
            if (expectedResult.getExpectedResult()) {
                fail(expectedResult.getMessage());
            }
            return;
        }
        if (!expectedResult.getExpectedResult()) {
            fail(expectedResult.getMessage());
        }
    }

    @DisplayName("Validate that SIOP-2 clients are properly translated to ClientRepresentations")
    @ParameterizedTest
    @MethodSource("provideOIDC4VPClients")
    public void testToClientRepresentation(OIDC4VPClient toTest, ExpectedResult<ClientRepresentation> expectedResult)
            throws IllegalAccessException {
        String errorMessage = compare(expectedResult.getExpectedResult(),
                OIDC4VPClientRegistrationProvider.toClientRepresentation(toTest));
        assertNull(errorMessage, String.format("%s - %s",
                expectedResult.getMessage(), errorMessage));
    }

    private static Stream<Arguments> provideOIDC4VPClients() {
        return Stream.of(
                Arguments.of(
                        new OIDC4VPClient("did:test:did", null, null, null, null, null),
                        new ExpectedResult(getClientRepresentation("did:test:did"),
                                "A valid client should have been created.")),
                Arguments.of(
                        new OIDC4VPClient("did:test:did", null, "my desc", null, null, null),
                        new ExpectedResult(getClientRepresentation("did:test:did", null, "my desc", null),
                                "A valid client should have been created.")),
                Arguments.of(
                        new OIDC4VPClient("did:test:did", null, "my desc", "my name", null, null),
                        new ExpectedResult(getClientRepresentation("did:test:did", "my name", "my desc", null),
                                "A valid client should have been created.")),
                Arguments.of(
                        new OIDC4VPClient("did:test:did", List.of(OIDC4VPIssuerEndpointTest.getCredential("PacketDeliveryService", Format.LDP_VC), OIDC4VPIssuerEndpointTest.getCredential("SomethingFancy", Format.LDP_VC)), null, null, null, null),
                        new ExpectedResult(getClientRepresentation("did:test:did", null, null,
                                Map.of("vctypes_PacketDeliveryService", Format.LDP_VC.toString(),
                                        "vctypes_SomethingFancy", Format.LDP_VC.toString())),
                                "A valid client should have been created.")),
                Arguments.of(new OIDC4VPClient("did:test:did", List.of(OIDC4VPIssuerEndpointTest.getCredential("PacketDeliveryService", Format.LDP_VC), OIDC4VPIssuerEndpointTest.getCredential("SomethingFancy", Format.LDP_VC)), null, null, null,
                                Map.of("additional", "claim", "another", "one")),
                        new ExpectedResult(getClientRepresentation("did:test:did", null, null,
                                Map.of(
                                        "vc_another", "one",
                                        "vc_additional", "claim",
                                        "vctypes_PacketDeliveryService", Format.LDP_VC.toString(),
                                        "vctypes_SomethingFancy", Format.LDP_VC.toString())),
                                "A valid client should have been created.")),
                Arguments.of(new OIDC4VPClient("did:test:did", List.of(OIDC4VPIssuerEndpointTest.getCredential("PacketDeliveryService", Format.LDP_VC), OIDC4VPIssuerEndpointTest.getCredential("SomethingFancy", Format.LDP_VC)), null, null,
                                1000l,
                                Map.of("additional", "claim", "another", "one")),
                        new ExpectedResult(getClientRepresentation("did:test:did", null, null,
                                Map.of(
                                        "vc_another", "one",
                                        "vc_additional", "claim",
                                        "vctypes_PacketDeliveryService", Format.LDP_VC.toString(),
                                        "vctypes_SomethingFancy", Format.LDP_VC.toString())),
                                "A valid client should have been created."))
        );
    }

    private static Stream<Arguments> provideClientRepresentations() {
        return Stream.of(
                Arguments.of(getClientRepresentation("invalidId"),
                        new ExpectedResult(false, "Only valid DIDs are accepted.")),
                Arguments.of(getClientRepresentation(null), new ExpectedResult(false, "Null is not a valid DID.")),
                Arguments.of(getClientRepresentation("did-key-mykey"),
                        new ExpectedResult(false, "Only valid DIDs are accepted.")),
                Arguments.of(getClientRepresentation("did:key:mykey"),
                        new ExpectedResult(true, "Valid DIDs should be accepted."))
        );
    }

    private static ClientRepresentation getClientRepresentation(String clientId) {
        return getClientRepresentation(clientId, null, null, null);
    }

    private static ClientRepresentation getClientRepresentation(String clientId, String name, String description,
                                                                Map<String, String> additionalClaims) {
        ClientRepresentation cr = new ClientRepresentation();
        cr.setClientId(clientId);
        cr.setId(clientId);
        cr.setProtocol(OIDC4VPClientRegistrationProviderFactory.PROTOCOL_ID);
        cr.setAttributes(additionalClaims);
        cr.setDescription(description);
        cr.setName(name);

        return cr;
    }

    // client representation does not implement equals and serialization does not gurantee order of maps and lists, thus
    // we use reflections to compare them
    private static String compare(ClientRepresentation c1, ClientRepresentation c2) throws IllegalAccessException {

        Optional<Field> notEqualsField = Arrays.stream(ClientRepresentation.class.getDeclaredFields())
                .peek(field -> field.setAccessible(true))
                .filter(field -> {
                    if (field.getName() == "id") {
                        // ignore the id, since it's a random uuid
                        return false;
                    }
                    try {
                        var v1 = field.get(c1);
                        var v2 = field.get(c2);
                        if (v1 == null && v2 == null) {
                            return false;
                        }
                        return !v1.equals(v2);
                    } catch (IllegalAccessException e) {
                        LOGGER.warn("Was not able to access field.", e);
                        return true;
                    }
                }).findFirst();
        if (notEqualsField.isPresent()) {
            Field f = notEqualsField.get();
            var v1 = f.get(c1);
            var v2 = f.get(c2);
            return String.format("Field %s does not match. V1: %s V2: %s", notEqualsField.toString(), v1, v2);
        }
        return null;
    }

}