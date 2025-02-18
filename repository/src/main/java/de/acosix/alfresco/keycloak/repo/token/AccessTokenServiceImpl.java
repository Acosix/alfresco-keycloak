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
package de.acosix.alfresco.keycloak.repo.token;

import java.util.Collection;

import org.alfresco.util.ParameterCheck;
import org.alfresco.util.PropertyCheck;
import org.keycloak.adapters.KeycloakDeployment;
import org.springframework.beans.factory.InitializingBean;

import de.acosix.alfresco.keycloak.repo.util.RefreshableAccessTokenHolder;

/**
 * Instances of this class provide the technical implementation of the service interface.
 *
 * @author Axel Faust
 */
public class AccessTokenServiceImpl implements AccessTokenService, InitializingBean
{

    protected KeycloakDeployment deployment;

    protected AccessTokenClient accessTokenClient;

    /**
     *
     * {@inheritDoc}
     */
    @Override
    public void afterPropertiesSet()
    {
        PropertyCheck.mandatory(this, "deployment", this.deployment);
        this.accessTokenClient = new AccessTokenClient(this.deployment);
    }

    /**
     * @param deployment
     *     the deployment to set
     */
    public void setDeployment(final KeycloakDeployment deployment)
    {
        this.deployment = deployment;
    }

    /**
     *
     * {@inheritDoc}
     */
    @Override
    public AccessTokenHolder obtainAccessToken(final Collection<String> scopes)
    {
        ParameterCheck.mandatory("scopes", scopes);
        final RefreshableAccessTokenHolder refreshableToken = this.accessTokenClient.obtainAccessToken(scopes);

        return new AccessTokenHolderImpl(refreshableToken, this.deployment.getTokenMinimumTimeToLive(),
                this.accessTokenClient::refreshAccessToken, () -> {
                    try
                    {
                        return this.accessTokenClient.obtainAccessToken(scopes);
                    }
                    catch (final AccessTokenException atex)
                    {
                        throw new AccessTokenRefreshException("Error re-obtaining access token as part of refresh", atex);
                    }
                });
    }

    /**
     *
     * {@inheritDoc}
     */
    @Override
    public AccessTokenHolder obtainAccessToken(final String user, final String password, final Collection<String> scopes)
    {
        ParameterCheck.mandatoryString("user", user);
        ParameterCheck.mandatoryString("password", password);

        final RefreshableAccessTokenHolder refreshableToken = this.accessTokenClient.obtainAccessToken(user, password, scopes);

        return new AccessTokenHolderImpl(refreshableToken, this.deployment.getTokenMinimumTimeToLive(),
                this.accessTokenClient::refreshAccessToken, () -> {
                    try
                    {
                        return this.accessTokenClient.obtainAccessToken(user, password, scopes);
                    }
                    catch (final AccessTokenException atex)
                    {
                        throw new AccessTokenRefreshException("Error re-obtaining access token as part of refresh", atex);
                    }
                });
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public AccessTokenHolder exchangeToken(final String accessToken, final String client, final Collection<String> scopes)
    {
        ParameterCheck.mandatoryString("accessToken", accessToken);
        ParameterCheck.mandatoryString("client", client);

        final RefreshableAccessTokenHolder refreshableToken = this.accessTokenClient.exchangeToken(accessToken, client, scopes);

        return new AccessTokenHolderImpl(refreshableToken, this.deployment.getTokenMinimumTimeToLive(), refreshToken -> {
            try
            {
                final String newAccessToken = this.accessTokenClient.refreshAccessToken(refreshToken).getToken();
                return this.accessTokenClient.exchangeToken(newAccessToken, client, scopes);
            }
            catch (final AccessTokenException atex)
            {
                throw new AccessTokenRefreshException("Error re-obtaining access token as part of refresh", atex);
            }
        });
    }

}
