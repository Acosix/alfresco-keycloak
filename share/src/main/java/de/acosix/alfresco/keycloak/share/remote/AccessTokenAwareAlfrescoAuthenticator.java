/*
 * Copyright 2019 - 2021 Acosix GmbH
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
package de.acosix.alfresco.keycloak.share.remote;

import jakarta.servlet.http.HttpSession;

import org.keycloak.adapters.OidcKeycloakAccount;
import org.keycloak.adapters.spi.KeycloakAccount;
import org.springframework.extensions.surf.ServletUtil;
import org.springframework.extensions.webscripts.connector.ConnectorSession;

import de.acosix.alfresco.keycloak.share.util.RefreshableAccessTokenHolder;
import de.acosix.alfresco.keycloak.share.web.KeycloakAuthenticationFilter;
import de.acosix.alfresco.utility.share.connector.FlexibleAlfrescoAuthenticator;

/**
 * @author Axel Faust
 */
public class AccessTokenAwareAlfrescoAuthenticator extends FlexibleAlfrescoAuthenticator
{

    /**
     *
     * {@inheritDoc}
     */
    @Override
    public boolean isAuthenticated(final String endpoint, final ConnectorSession connectorSession)
    {
        boolean authenticated = super.isAuthenticated(endpoint, connectorSession);

        if (!authenticated)
        {
            final HttpSession session = ServletUtil.getSession();
            final KeycloakAccount keycloakAccount = (KeycloakAccount) (session != null
                    ? session.getAttribute(KeycloakAuthenticationFilter.KEYCLOAK_ACCOUNT_SESSION_KEY)
                    : null);
            final RefreshableAccessTokenHolder accessToken = (RefreshableAccessTokenHolder) (session != null
                    ? session.getAttribute(KeycloakAuthenticationFilter.ACCESS_TOKEN_SESSION_KEY)
                    : null);
            final RefreshableAccessTokenHolder endpointSpecificAccessToken = (RefreshableAccessTokenHolder) (session != null
                    ? session.getAttribute(KeycloakAuthenticationFilter.BACKEND_ACCESS_TOKEN_SESSION_KEY)
                    : null);

            authenticated = endpointSpecificAccessToken != null && endpointSpecificAccessToken.isActive()
                    || keycloakAccount instanceof OidcKeycloakAccount || accessToken != null;
        }

        return authenticated;
    }
}
