package org.keycloak.protocol.oid4vp;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.ws.rs.core.UriInfo;
import org.keycloak.models.KeycloakContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.protocol.oid4vp.model.Format;
import org.keycloak.protocol.oid4vp.model.SupportedCredential;
import org.keycloak.services.Urls;
import org.keycloak.urls.UrlType;
import org.keycloak.wellknown.WellKnownProvider;

import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import static org.keycloak.protocol.oid4vp.OIDC4VPClientRegistrationProvider.VC_TYPES_PREFIX;

public abstract class OIDC4VPAbstractWellKnownProvider implements WellKnownProvider {

	protected final KeycloakSession keycloakSession;
	protected final ObjectMapper objectMapper;

	protected OIDC4VPAbstractWellKnownProvider(KeycloakSession keycloakSession,
			ObjectMapper objectMapper) {
		this.keycloakSession = keycloakSession;
		this.objectMapper = objectMapper;
	}

	public static List<SupportedCredential> getSupportedCredentials(KeycloakContext context) {

		return context.getRealm().getClientsStream()
				.flatMap(cm -> cm.getAttributes().entrySet().stream())
				.filter(entry -> entry.getKey().startsWith(VC_TYPES_PREFIX))
				.flatMap(entry -> mapAttributeEntryToScVO(entry).stream())
				.toList();

	}

	protected List<SupportedCredential> mapAttributeEntryToSc(Map.Entry<String, String> typesEntry) {
		String type = typesEntry.getKey().replaceFirst(VC_TYPES_PREFIX, "");
		Set<Format> supportedFormats = getFormatsFromString(typesEntry.getValue());
		return supportedFormats.stream().map(formatVO -> {
					var scVO = new SupportedCredential();
					scVO.setTypes(List.of(type));
					scVO.setFormat(formatVO);
					return scVO;
				})
				.toList();
	}

	protected static List<SupportedCredential> mapAttributeEntryToScVO(Map.Entry<String, String> typesEntry) {
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

	protected static Set<Format> getFormatsFromString(String formatString) {
		return Arrays.stream(formatString.split(",")).map(Format::fromString).collect(Collectors.toSet());
	}

	protected static String buildIdFromType(Format formatVO, String type) {
		return String.format("%s_%s", type, formatVO.toString());
	}

	protected static String getIssuer(KeycloakContext context) {
		UriInfo frontendUriInfo = context.getUri(UrlType.FRONTEND);

		return Urls.realmIssuer(frontendUriInfo.getBaseUri(),
				context.getRealm().getName());

	}

	protected static String getCredentialsEndpoint(KeycloakContext context) {
		return getIssuer(context) + "/protocol/" + OIDC4VPLoginProtocolFactory.PROTOCOL_ID + "/credential";
	}
}
