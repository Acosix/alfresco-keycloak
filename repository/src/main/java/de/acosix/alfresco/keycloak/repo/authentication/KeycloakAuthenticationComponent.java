/*
 * Copyright 2019 Acosix GmbH
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

import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.TimeUnit;

import org.alfresco.repo.management.subsystems.ActivateableBean;
import org.alfresco.repo.security.authentication.AbstractAuthenticationComponent;
import org.alfresco.repo.security.authentication.AuthenticationException;
import org.alfresco.util.PropertyCheck;
import org.keycloak.adapters.HttpClientBuilder;
import org.keycloak.authorization.client.AuthzClient;
import org.keycloak.authorization.client.Configuration;
import org.keycloak.authorization.client.util.HttpResponseException;
import org.keycloak.representations.adapters.config.AdapterConfig;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.InitializingBean;

/**
 * @author Axel Faust
 */
public class KeycloakAuthenticationComponent extends AbstractAuthenticationComponent implements ActivateableBean, InitializingBean
{

    private static final Logger LOGGER = LoggerFactory.getLogger(KeycloakAuthenticationComponent.class);

    protected boolean active;

    protected boolean allowUserNamePasswordLogin;

    protected boolean allowGuestLogin;

    protected AdapterConfig adapterConfig;

    protected int connectionTimeout;

    protected int socketTimeout;

    protected Configuration config;

    protected AuthzClient authzClient;

    /**
     *
     * {@inheritDoc}
     */
    @Override
    public void afterPropertiesSet()
    {
        PropertyCheck.mandatory(this, "adapterConfig", this.adapterConfig);

        if (this.allowUserNamePasswordLogin)
        {
            Map<String, Object> credentials = this.adapterConfig.getCredentials();
            if (credentials != null)
            {
                credentials = new HashMap<>(credentials);
            }

            if (credentials == null || ((!credentials.containsKey("provider") || "secret".equals(credentials.get("provider")))
                    && !credentials.containsKey("secret")))
            {
                if (credentials == null)
                {
                    credentials = new HashMap<>();
                }
                credentials.put("secret", "");
            }

            HttpClientBuilder httpClientBuilder = new HttpClientBuilder();
            if (this.connectionTimeout > 0)
            {
                httpClientBuilder = httpClientBuilder.establishConnectionTimeout(this.connectionTimeout, TimeUnit.MILLISECONDS);
            }
            if (this.socketTimeout > 0)
            {
                httpClientBuilder = httpClientBuilder.socketTimeout(this.socketTimeout, TimeUnit.MILLISECONDS);
            }

            this.config = new Configuration(this.adapterConfig.getAuthServerUrl(), this.adapterConfig.getRealm(),
                    this.adapterConfig.getResource(), credentials, httpClientBuilder.build(this.adapterConfig));
            try
            {
                this.authzClient = AuthzClient.create(this.config);
            }
            catch (final RuntimeException e)
            {
                if (LOGGER.isDebugEnabled())
                {
                    LOGGER.debug("Failed to pre-instantiate Keycloak authz client", e);
                }
                else
                {
                    LOGGER.warn("Failed to pre-instantiate Keycloak authz client: {}", e.getMessage());
                }
            }
        }
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
     * @param allowUserNamePasswordLogin
     *            the allowUserNamePasswordLogin to set
     */
    public void setAllowUserNamePasswordLogin(final boolean allowUserNamePasswordLogin)
    {
        this.allowUserNamePasswordLogin = allowUserNamePasswordLogin;
    }

    /**
     * @param allowGuestLogin
     *            the allowGuestLogin to set
     */
    public void setAllowGuestLogin(final boolean allowGuestLogin)
    {
        this.allowGuestLogin = allowGuestLogin;
    }

    /**
     * @param adapterConfig
     *            the adapterConfig to set
     */
    public void setAdapterConfig(final AdapterConfig adapterConfig)
    {
        this.adapterConfig = adapterConfig;
    }

    /**
     * @param connectionTimeout
     *            the connectionTimeout to set
     */
    public void setConnectionTimeout(final int connectionTimeout)
    {
        this.connectionTimeout = connectionTimeout;
    }

    /**
     * @param socketTimeout
     *            the socketTimeout to set
     */
    public void setSocketTimeout(final int socketTimeout)
    {
        this.socketTimeout = socketTimeout;
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
    public void authenticateImpl(final String userName, final char[] password) throws AuthenticationException
    {
        if (!this.allowUserNamePasswordLogin)
        {
            throw new AuthenticationException("Simple login via user name + password is not allowed");
        }

        if (this.authzClient == null)
        {
            try
            {
                this.authzClient = AuthzClient.create(this.config);
            }
            catch (final RuntimeException e)
            {
                LOGGER.warn("Failed to pre-instantiate Keycloak authz client", e);
                throw new AuthenticationException("Keycloak authentication cannot be performed", e);
            }
        }

        try
        {
            this.authzClient.obtainAccessToken(userName, new String(password));
            this.setCurrentUser(userName);
        }
        catch (final HttpResponseException e)
        {
            LOGGER.debug("Failed to authenticate user against Keycloak. Status: {} Reason: {}", e.getStatusCode(), e.getReasonPhrase());
            throw new AuthenticationException("Failed to authenticate user against Keycloak.", e);
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    protected boolean implementationAllowsGuestLogin()
    {
        return this.allowGuestLogin;
    }
}
