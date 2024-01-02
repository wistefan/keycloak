package org.keycloak.protocol.oid4vc;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.ws.rs.core.UriInfo;
import org.keycloak.models.KeycloakContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.protocol.oid4vc.model.Format;
import org.keycloak.protocol.oid4vc.model.SupportedCredential;
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

    protected final KeycloakSession keycloakSession;
    protected final ObjectMapper objectMapper;

    protected OID4VPAbstractWellKnownProvider(KeycloakSession keycloakSession,
                                              ObjectMapper objectMapper) {
        this.keycloakSession = keycloakSession;
        this.objectMapper = objectMapper;
    }

    public static List<SupportedCredential> getSupportedCredentials(KeycloakContext context) {

        RealmModel realmModel = context.getRealm();
        List<Format> supportedFormats = new ArrayList<>();
        Optional.ofNullable(realmModel.getAttribute("sdJwtVcEnabled"))
                .map(Boolean::valueOf)
                .filter(enabled -> enabled)
                .map(e -> Format.SD_JWT_VC)
                .ifPresent(supportedFormats::add);
        Optional.ofNullable(realmModel.getAttribute("jwtVcEnabled"))
                .map(Boolean::valueOf)
                .filter(enabled -> enabled)
                .map(e -> Format.JWT_VC)
                .ifPresent(supportedFormats::add);
        Optional.ofNullable(realmModel.getAttribute("vcdmEnabled"))
                .map(Boolean::valueOf)
                .filter(enabled -> enabled)
                .map(e -> Format.LDP_VC)
                .ifPresent(supportedFormats::add);


        return context.getRealm().getClientsStream()
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
