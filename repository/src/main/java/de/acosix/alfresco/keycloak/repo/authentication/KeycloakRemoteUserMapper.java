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
package de.acosix.alfresco.keycloak.repo.authentication;

import java.util.List;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;

import org.alfresco.repo.management.subsystems.ActivateableBean;
import org.alfresco.repo.security.authentication.AuthenticationException;
import org.alfresco.repo.security.authentication.AuthenticationUtil;
import org.alfresco.repo.security.authentication.external.RemoteUserMapper;
import org.alfresco.service.cmr.security.PersonService;
import org.alfresco.util.PropertyCheck;
import org.keycloak.adapters.BearerTokenRequestAuthenticator;
import org.keycloak.adapters.KeycloakDeployment;
import org.keycloak.adapters.spi.AuthOutcome;
import org.keycloak.representations.AccessToken;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.InitializingBean;

/**
 * @author Axel Faust
 */
public class KeycloakRemoteUserMapper implements RemoteUserMapper, ActivateableBean, InitializingBean
{

    private static final Logger LOGGER = LoggerFactory.getLogger(KeycloakRemoteUserMapper.class);

    protected boolean active;

    protected boolean validationFailureSilent;

    protected KeycloakDeployment keycloakDeployment;

    protected PersonService personService;

    /**
     *
     * {@inheritDoc}
     */
    @Override
    public void afterPropertiesSet()
    {
        PropertyCheck.mandatory(this, "keycloakDeployment", this.keycloakDeployment);
        PropertyCheck.mandatory(this, "personService", this.personService);

        this.keycloakDeployment.setBearerOnly(true);
    }

    /**
     * @param active
     *            the active to set
     */
    public void setActive(final boolean active)
    {
        this.active = active;
    }

    /**
     * @param validationFailureSilent
     *            the validationFailureSilent to set
     */
    public void setValidationFailureSilent(final boolean validationFailureSilent)
    {
        this.validationFailureSilent = validationFailureSilent;
    }

    /**
     * @param keycloakDeployment
     *            the keycloakDeployment to set
     */
    public void setKeycloakDeployment(final KeycloakDeployment keycloakDeployment)
    {
        this.keycloakDeployment = keycloakDeployment;
    }

    /**
     * @param personService
     *            the personService to set
     */
    public void setPersonService(final PersonService personService)
    {
        this.personService = personService;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public boolean isActive()
    {
        return this.active;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public String getRemoteUser(final HttpServletRequest request)
    {
        String remoteUser = null;
        if (this.active)
        {
            final ResponseHeaderCookieCaptureServletHttpFacade httpFacade = new ResponseHeaderCookieCaptureServletHttpFacade(request);
            final BearerTokenRequestAuthenticator authenticator = new BearerTokenRequestAuthenticator(this.keycloakDeployment);
            final AuthOutcome authOutcome = authenticator.authenticate(httpFacade);

            if (authOutcome == AuthOutcome.AUTHENTICATED)
            {
                final AccessToken token = authenticator.getToken();
                final String preferredUsername = token.getPreferredUsername();

                // need to store token for later validation
                final HttpSession session = request.getSession(true);
                session.setAttribute(KeycloakRemoteUserMapper.class.getName(), token);

                // need case distinction to avoid user name being nulled when user does not exist yet
                final String normalisedUserName = AuthenticationUtil.runAsSystem(
                        () -> this.personService.personExists(preferredUsername) ? this.personService.getUserIdentifier(preferredUsername)
                                : preferredUsername);

                // normally Alfresco masks user names in logging, but in this case it would run counter to the purpose of logging
                LOGGER.debug("Authenticated user {} via bearer token, normalised as {}", preferredUsername, normalisedUserName);

                remoteUser = normalisedUserName;
            }
            else if (authOutcome == AuthOutcome.FAILED)
            {
                authenticator.getChallenge().challenge(httpFacade);
                final List<String> authenticateHeader = httpFacade.getHeaders().get("WWW-Authenticate");
                String errorDescription = null;
                if (authenticateHeader != null && !authenticateHeader.isEmpty())
                {
                    final String headerValue = authenticateHeader.get(0);
                    final int idx = headerValue.indexOf(", error_description=\"");
                    if (idx != -1)
                    {
                        final int startIdx = idx + ", error_description=\"".length();
                        errorDescription = headerValue.substring(startIdx, headerValue.indexOf('"', startIdx));
                    }
                }

                LOGGER.debug("Bearer token authentication failed due to: {}", errorDescription);

                if (!this.validationFailureSilent)
                {
                    throw new AuthenticationException("Token validation failed: " + errorDescription);
                }
            }
        }

        return remoteUser;
    }
}
