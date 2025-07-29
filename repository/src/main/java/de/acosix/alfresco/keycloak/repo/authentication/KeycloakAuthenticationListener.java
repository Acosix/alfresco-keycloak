/*
 * Copyright 2019 - 2025 Acosix GmbH
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
package de.acosix.alfresco.keycloak.repo.authentication;

import org.alfresco.repo.cache.SimpleCache;
import org.alfresco.repo.web.auth.AuthenticationListener;
import org.alfresco.repo.web.auth.TicketCredentials;
import org.alfresco.repo.web.auth.WebCredentials;
import org.alfresco.service.cmr.security.AuthenticationService;
import org.alfresco.util.PropertyCheck;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.InitializingBean;

import de.acosix.alfresco.keycloak.repo.util.AlfrescoCompatibilityUtil;
import de.acosix.alfresco.keycloak.repo.util.RefreshableAccessTokenHolder;

/**
 * This class provides a central listener for ticket-based authentications to ensure that any ticket-associated Keycloak access tokens are
 * processed. This is made necessary by the fact that the Alfresco web script framework may discard any global authentication and
 * re-authenticate the user by validating the ticket in the HTTP session, thus losing any effect of the access token processing in the
 * global authentication. Additionally, in some cases the web script framework does not even check the authenticated session user and just
 * sets a remotely authenticated user as the current user - in that case at least it informs of a pseudo-ticket-based authentication, which
 * - due to Alfresco standard behaviour of one-ticket-per-user - reuses the same ticket the user already had been assigned.
 *
 * In short, Alfresco authentication is extremely inconsistent and this listener class helps to plug one more hole.
 *
 * @author Axel Faust
 */
public class KeycloakAuthenticationListener implements InitializingBean, AuthenticationListener
{

    private static final Logger LOGGER = LoggerFactory.getLogger(KeycloakAuthenticationListener.class);

    protected AuthenticationService authenticationService;

    protected KeycloakAuthenticationComponent keycloakAuthenticationComponent;

    protected SimpleCache<String, RefreshableAccessTokenHolder> keycloakTicketTokenCache;

    /**
     *
     * {@inheritDoc}
     */
    @Override
    public void afterPropertiesSet()
    {
        PropertyCheck.mandatory(this, "authenticationService", this.authenticationService);
        PropertyCheck.mandatory(this, "keycloakAuthenticationCompoennt", this.keycloakAuthenticationComponent);
        PropertyCheck.mandatory(this, "keycloakTicketTokenCache", this.keycloakTicketTokenCache);
    }

    /**
     *
     * {@inheritDoc}
     */
    @Override
    public void userAuthenticated(final WebCredentials credentials)
    {
        if (credentials instanceof TicketCredentials)
        {
            // for whatever reason, the credentials don't expose the ticket
            final String ticket = this.authenticationService.getCurrentTicket();
            if (this.keycloakTicketTokenCache.contains(ticket))
            {
                final RefreshableAccessTokenHolder token = this.keycloakTicketTokenCache.get(ticket);
                LOGGER.debug("Processing access token for {} after ticket-based authentication",
                        AlfrescoCompatibilityUtil.maskUsername(token.getAccessToken().getPreferredUsername()));
                // any ticket-based authentication is not a fresh login as it reuses obtained authentications
                this.keycloakAuthenticationComponent.handleUserTokens(token.getAccessToken(), token.getIdToken(), false);
            }
        }
    }

    /**
     *
     * {@inheritDoc}
     */
    @Override
    public void authenticationFailed(final WebCredentials credentials, final Exception ex)
    {
        // NO-OP
    }

    /**
     *
     * {@inheritDoc}
     */
    @Override
    public void authenticationFailed(final WebCredentials credentials)
    {
        // NO-OP
    }

    /**
     * @param authenticationService
     *            the authenticationService to set
     */
    public void setAuthenticationService(final AuthenticationService authenticationService)
    {
        this.authenticationService = authenticationService;
    }

    /**
     * @param keycloakAuthenticationComponent
     *            the keycloakAuthenticationComponent to set
     */
    public void setKeycloakAuthenticationComponent(final KeycloakAuthenticationComponent keycloakAuthenticationComponent)
    {
        this.keycloakAuthenticationComponent = keycloakAuthenticationComponent;
    }

    /**
     * @param keycloakTicketTokenCache
     *            the keycloakTicketTokenCache to set
     */
    public void setKeycloakTicketTokenCache(final SimpleCache<String, RefreshableAccessTokenHolder> keycloakTicketTokenCache)
    {
        this.keycloakTicketTokenCache = keycloakTicketTokenCache;
    }

}
