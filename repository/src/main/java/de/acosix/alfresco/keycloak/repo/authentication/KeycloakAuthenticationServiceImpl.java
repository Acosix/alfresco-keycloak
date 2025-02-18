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
import org.alfresco.repo.security.authentication.AuthenticationException;
import org.alfresco.repo.security.authentication.AuthenticationServiceImpl;
import org.alfresco.repo.security.authentication.AuthenticationUtil;
import org.alfresco.repo.security.authentication.TicketComponent;
import org.alfresco.util.PropertyCheck;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.InitializingBean;

import de.acosix.alfresco.keycloak.repo.util.AlfrescoCompatibilityUtil;
import de.acosix.alfresco.keycloak.repo.util.RefreshableAccessTokenHolder;

/**
 * Instances of this specialised authentication service sub-class keep track of Keycloak token responses to password-based logins, and
 * validate / refresh the Keycloak session whenever the associated user authentication ticket is validated.
 *
 * @author Axel Faust
 */
public class KeycloakAuthenticationServiceImpl extends AuthenticationServiceImpl implements InitializingBean
{

    private static final Logger LOGGER = LoggerFactory.getLogger(KeycloakAuthenticationServiceImpl.class);

    // need to copy these fields from base class because they are package-protected there
    protected KeycloakAuthenticationComponent authenticationComponent;

    protected TicketComponent ticketComponent;

    protected SimpleCache<String, RefreshableAccessTokenHolder> keycloakTicketTokenCache;

    /**
     *
     * {@inheritDoc}
     */
    @Override
    public void afterPropertiesSet()
    {
        PropertyCheck.mandatory(this, "authenticationComponent", this.authenticationComponent);
        PropertyCheck.mandatory(this, "ticketComponent", this.ticketComponent);
        PropertyCheck.mandatory(this, "keycloakTicketTokenCache", this.keycloakTicketTokenCache);
    }

    /**
     * @param authenticationComponent
     *            the authenticationComponent to set
     */
    public void setAuthenticationComponent(final KeycloakAuthenticationComponent authenticationComponent)
    {
        this.authenticationComponent = authenticationComponent;
        super.setAuthenticationComponent(authenticationComponent);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void setTicketComponent(final TicketComponent ticketComponent)
    {
        this.ticketComponent = ticketComponent;
        super.setTicketComponent(ticketComponent);
    }

    /**
     * @param keycloakTicketTokenCache
     *            the keycloakTicketTokenCache to set
     */
    public void setKeycloakTicketTokenCache(final SimpleCache<String, RefreshableAccessTokenHolder> keycloakTicketTokenCache)
    {
        this.keycloakTicketTokenCache = keycloakTicketTokenCache;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void authenticate(final String userName, final char[] password) throws AuthenticationException
    {
        this.authenticationComponent.enableLastTokenStore();
        try
        {
            super.authenticate(userName, password);

            final RefreshableAccessTokenHolder lastTokenResponse = this.authenticationComponent.getLastTokenResponse();
            if (lastTokenResponse != null)
            {
                final String currentTicket = this.getCurrentTicket();
                LOGGER.debug("Associating ticket {} for user {} with Keycloak access token", currentTicket,
                        AlfrescoCompatibilityUtil.maskUsername(userName));
                this.keycloakTicketTokenCache.put(currentTicket, lastTokenResponse);
            }
        }
        finally
        {
            this.authenticationComponent.disableLastTokenStore();
        }
    }

    /**
     *
     * {@inheritDoc}
     */
    @Override
    public void validate(final String ticket) throws AuthenticationException
    {
        super.validate(ticket);

        if (this.keycloakTicketTokenCache.contains(ticket))
        {
            final RefreshableAccessTokenHolder refreshableAccessToken = this.keycloakTicketTokenCache.get(ticket);
            try
            {
                final RefreshableAccessTokenHolder refreshedToken = this.authenticationComponent
                        .checkAndRefreshTicketToken(refreshableAccessToken);
                if (refreshedToken != null)
                {
                    this.keycloakTicketTokenCache.put(ticket, refreshedToken);
                }
                // apparently expiration is allowed - remove from cache to avoid unnecessary checks in the future
                else if (!refreshableAccessToken.isActive())
                {
                    LOGGER.warn(
                            "The Keycloak access token associated with ticket {} for user {} has expired - Keycloak roles / claims are no longer available for the corresponding user",
                            ticket, AlfrescoCompatibilityUtil.maskUsername(AuthenticationUtil.getFullyAuthenticatedUser()));
                    this.keycloakTicketTokenCache.remove(ticket);
                }
            }
            catch (final AuthenticationException ae)
            {
                this.clearCurrentSecurityContext();
                throw ae;
            }
        }
    }
}
