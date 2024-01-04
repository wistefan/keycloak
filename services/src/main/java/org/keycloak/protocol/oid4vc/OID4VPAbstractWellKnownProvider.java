package org.keycloak.protocol.oid4vc;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.ws.rs.core.UriInfo;
import org.jboss.logging.Logger;
import org.keycloak.models.KeycloakContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.protocol.oid4vc.issuance.OID4VPIssuerEndpoint;
import org.keycloak.protocol.oid4vc.issuance.signing.VCSigningServiceProviderFactory;
import org.keycloak.protocol.oid4vc.issuance.signing.VerifiableCredentialsSigningService;
import org.keycloak.protocol.oid4vc.model.Format;
import org.keycloak.protocol.oid4vc.model.SupportedCredential;
import org.keycloak.provider.ProviderFactory;
import org.keycloak.services.Urls;
import org.keycloak.urls.UrlType;
import org.keycloak.wellknown.WellKnownProvider;

import java.util.*;
import java.util.stream.Collectors;

import static org.keycloak.protocol.oid4vc.OID4VPClientRegistrationProvider.VC_TYPES_PREFIX;

/**
 * Super class for the OID4VC focused {@link  WellKnownProvider}
 *
 * @author <a href="https://github.com/wistefan">Stefan Wiedemann</a>
 */
public abstract class OID4VPAbstractWellKnownProvider implements WellKnownProvider {

    private static final Logger LOGGER = Logger.getLogger(OID4VPAbstractWellKnownProvider.class);
    protected final KeycloakSession keycloakSession;
    protected final ObjectMapper objectMapper;

    protected OID4VPAbstractWellKnownProvider(KeycloakSession keycloakSession,
                                              ObjectMapper objectMapper) {
        this.keycloakSession = keycloakSession;
        this.objectMapper = objectMapper;
    }

    public static List<SupportedCredential> getSupportedCredentials(KeycloakSession keycloakSession) {
        LOGGER.debug("Get supported credentials.");
        var realm = keycloakSession.getContext().getRealm();
        List<Format> supportedFormats = realm.getComponentsStream(realm.getId(), VerifiableCredentialsSigningService.class.getName())
                .map(cm ->
                        keycloakSession
                                .getKeycloakSessionFactory()
                                .getProviderFactory(VerifiableCredentialsSigningService.class, cm.getProviderId())
                )
                .filter(pf -> pf instanceof VCSigningServiceProviderFactory)
                .map(sspf -> (VCSigningServiceProviderFactory) sspf)
                .map(VCSigningServiceProviderFactory::supportedFormat)
                .toList();


        return keycloakSession.getContext().getRealm().getClientsStream()
                .flatMap(cm -> cm.getAttributes().entrySet().stream())
                .filter(entry -> entry.getKey().startsWith(VC_TYPES_PREFIX))
                .flatMap(entry -> mapAttributeEntryToScVO(entry).stream())
                .filter(supportedCredential -> supportedFormats.contains(supportedCredential.getFormat()))
                .distinct()
                .toList();

    }

    public static List<SupportedCredential> mapAttributeEntryToScVO(Map.Entry<String, String> typesEntry) {
        String type = typesEntry.getKey().replaceFirst(VC_TYPES_PREFIX, "");
        Set<Format> supportedFormats = getFormatsFromString(typesEntry.getValue());
        return supportedFormats.stream().map(formatVO -> {
                    String id = buildIdFromType(formatVO, type);
                    return new SupportedCredential()
                            .id(id)
                            .format(formatVO)
                            .types(List.of(type))
                            .cryptographicBindingMethodsSupported(List.of("did"))
                            .cryptographicSuitesSupported(List.of("Ed25519Signature2018"));
                }
        ).toList();
    }

    public static Set<Format> getFormatsFromString(String formatString) {
        return Arrays.stream(formatString.split(",")).map(Format::fromString).collect(Collectors.toSet());
    }

    public static String buildIdFromType(Format formatVO, String type) {
        return String.format("%s_%s", type, formatVO.toString());
    }

    public static String getIssuer(KeycloakContext context) {
        UriInfo frontendUriInfo = context.getUri(UrlType.FRONTEND);

        return Urls.realmIssuer(frontendUriInfo.getBaseUri(),
                context.getRealm().getName());

    }

    public static String getCredentialsEndpoint(KeycloakContext context) {
        return getIssuer(context) + "/protocol/" + OID4VPLoginProtocolFactory.PROTOCOL_ID + "/credential";
    }
}
