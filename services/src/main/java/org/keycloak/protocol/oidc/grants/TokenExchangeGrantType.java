/*
 * Copyright 2024 Red Hat, Inc. and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.keycloak.protocol.oidc.grants;

import jakarta.ws.rs.InternalServerErrorException;
import jakarta.ws.rs.core.Response;

import org.keycloak.OAuth2Constants;
import org.keycloak.common.Profile;
import org.keycloak.events.Details;
import org.keycloak.models.KeycloakSession;
import org.keycloak.protocol.oidc.TokenExchangeContext;
import org.keycloak.protocol.oidc.TokenExchangeProvider;
import org.keycloak.provider.EnvironmentDependentProviderFactory;
import org.keycloak.utils.ProfileHelper;

/**
 * OAuth 2.0 Authorization Code Grant
 * https://datatracker.ietf.org/doc/html/rfc8693#section-2.1
 *
 * @author <a href="mailto:demetrio@carretti.pro">Dmitry Telegin</a> (et al.)
 */
public class TokenExchangeGrantType extends OAuth2GrantTypeBase implements EnvironmentDependentProviderFactory {

    private static final String PROVIDER_ID = "token_exchange";

    @Override
    public Response process() {
        event.detail(Details.AUTH_METHOD, "token_exchange");
        event.client(client);

        TokenExchangeContext exchange = new TokenExchangeContext(
                session,
                formParams,
                cors,
                realm,
                event,
                client,
                clientConnection,
                headers,
                tokenManager,
                clientAuthAttributes);

        return session.getKeycloakSessionFactory()
                .getProviderFactoriesStream(TokenExchangeProvider.class)
                .sorted((f1, f2) -> f2.order() - f1.order())
                .map(f -> session.getProvider(TokenExchangeProvider.class, f.getId()))
                .filter(p -> p.supports(exchange))
                .findFirst()
                .orElseThrow(() -> new InternalServerErrorException("No token exchange provider available"))
                .exchange(exchange);
    }

    @Override
    public String getGrantType() {
        return OAuth2Constants.TOKEN_EXCHANGE_GRANT_TYPE;
    }

    @Override
    public OAuth2GrantType create(KeycloakSession session) {
        return new TokenExchangeGrantType();
    }

    @Override
    public boolean isSupported() {
        return Profile.isFeatureEnabled(Profile.Feature.TOKEN_EXCHANGE);
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

}
