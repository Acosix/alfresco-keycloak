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
package de.acosix.alfresco.keycloak.share.util;

import java.io.Serializable;

import org.alfresco.util.ParameterCheck;
import org.keycloak.adapters.rotation.AdapterTokenVerifier.VerifiedTokens;
import org.keycloak.common.util.Time;
import org.keycloak.representations.AccessToken;
import org.keycloak.representations.AccessTokenResponse;
import org.keycloak.representations.IDToken;

/**
 * Instances of this class encapsulate a potentially refreshable access token.
 *
 * @author Axel Faust
 */
public class RefreshableAccessTokenHolder implements Serializable
{

    private static final long serialVersionUID = -3230026569734591820L;

    protected final AccessToken accessToken;

    protected final IDToken idToken;

    protected final String token;

    protected final String refreshToken;

    protected final long refreshExpiration;

    /**
     * Constructs a new instance of this class from an access token response, typically from an initial authentication or token refresh
     *
     * @param tokenResponse
     *            the response to a request for an access token
     * @param verifiedTokens
     *            the token wrapper from the response verification step any client should do before constructing a new instance of this
     *            class
     */
    public RefreshableAccessTokenHolder(final AccessTokenResponse tokenResponse, final VerifiedTokens verifiedTokens)
    {
        ParameterCheck.mandatory("tokenResponse", tokenResponse);
        ParameterCheck.mandatory("verifiedTokens", verifiedTokens);

        this.accessToken = verifiedTokens.getAccessToken();
        this.idToken = verifiedTokens.getIdToken();

        this.token = tokenResponse.getToken();
        this.refreshToken = tokenResponse.getRefreshToken();
        this.refreshExpiration = Time.currentTime() + tokenResponse.getRefreshExpiresIn();
    }

    /**
     * Constructs a new instance of this class from details exposed by Keycloak servlet adapter APIs. Since these APIs do not provide some
     * access to token response details, this constructor assumes that the refresh token is valid for at least 1/100th the duration of the
     * overall access token.
     *
     * @param accessToken
     *            the access token
     * @param idToken
     *            the ID token
     * @param token
     *            the textual representation of the access token
     * @param refreshToken
     *            the textual representation of the refresh token
     */
    public RefreshableAccessTokenHolder(final AccessToken accessToken, final IDToken idToken, final String token, final String refreshToken)
    {
        ParameterCheck.mandatory("accessToken", accessToken);
        ParameterCheck.mandatory("idToken", idToken);
        ParameterCheck.mandatoryString("token", token);

        this.accessToken = accessToken;
        this.idToken = idToken;

        this.token = token;
        this.refreshToken = refreshToken;
        // no explicit refresh expiration, so assume validity period is 1/100th
        this.refreshExpiration = Time.currentTime() - (accessToken.getExp() - Time.currentTime()) / 100;
    }

    /**
     * Checks whether the encapsulated access token is active.
     *
     * @return {@code true} if the access token is active, {@code false} otherwise
     */
    public boolean isActive()
    {
        final boolean isActive = this.accessToken.isActive();
        return isActive;
    }

    /**
     * Checks whether the encapsulated access token has expired.
     *
     * @return {@code true} if the access token as expired, {@code false} otherwise
     */
    public boolean isExpired()
    {
        final boolean isExpired = this.accessToken.isExpired();
        return isExpired;
    }

    /**
     * Checks whether the encapsulated access token can be refreshed.
     *
     * @return {@code true} if the token can be refreshed, {@code false} otherwise
     */
    public boolean canRefresh()
    {
        final boolean canRefresh = this.refreshToken != null && this.refreshExpiration > Time.currentTime();
        return canRefresh;
    }

    /**
     * Checks whether the encapsulated access token should be refreshed.
     *
     * @param minTokenTTL
     *            the minimum time-to-live remaining before a token needs to be refreshed
     *
     * @return {@code true} if the token should be refreshed, {@code false} otherwise
     */
    public boolean shouldRefresh(final int minTokenTTL)
    {
        final boolean shouldRefresh = this.refreshToken != null && this.accessToken.getExp() - minTokenTTL < Time.currentTime();
        return shouldRefresh;
    }

    /**
     * @return the token
     */
    public String getToken()
    {
        return this.token;
    }

    /**
     * @return the refreshToken
     */
    public String getRefreshToken()
    {
        return this.refreshToken;
    }

    /**
     * @return the access token
     */
    public AccessToken getAccessToken()
    {
        return this.accessToken;
    }

    /**
     * @return the idToken
     */
    public IDToken getIdToken()
    {
        return this.idToken;
    }

}
