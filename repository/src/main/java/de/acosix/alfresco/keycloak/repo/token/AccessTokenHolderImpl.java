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

import java.util.concurrent.locks.ReentrantReadWriteLock;
import java.util.function.Function;
import java.util.function.Supplier;

import de.acosix.alfresco.keycloak.repo.util.RefreshableAccessTokenHolder;

/**
 * Instances of this class provide the technical implementation of the holder interface.
 *
 * @author Axel Faust
 */
public class AccessTokenHolderImpl implements AccessTokenHolder
{

    private final ReentrantReadWriteLock tokenLock = new ReentrantReadWriteLock(true);

    private RefreshableAccessTokenHolder token;

    private final int minimumTimeToLive;

    private final Function<String, RefreshableAccessTokenHolder> refresher;

    private Supplier<RefreshableAccessTokenHolder> obtainer;

    /**
     * Constructs a new instance of this class to wrap the provided initial access token.
     *
     * @param token
     *            the initial access token
     * @param minimumTimeToLive
     *            the minimum time to live for access tokens expected by the Keycloak deployment
     * @param refresher
     *            the callback function to refresh an expired access token
     */
    public AccessTokenHolderImpl(final RefreshableAccessTokenHolder token, final int minimumTimeToLive,
            final Function<String, RefreshableAccessTokenHolder> refresher)
    {
        this.token = token;
        this.minimumTimeToLive = minimumTimeToLive;
        this.refresher = refresher;
    }

    /**
     * Constructs a new instance of this class to wrap the provided initial access token.
     *
     * @param token
     *            the initial access token
     * @param minimumTimeToLive
     *            the minimum time to live for access tokens expected by the Keycloak deployment
     * @param refresher
     *            the callback function to refresh an expired access token
     * @param obtainer
     *            the supplier to re-obtain the access token after both access token and its refresh token have expired
     */
    public AccessTokenHolderImpl(final RefreshableAccessTokenHolder token, final int minimumTimeToLive,
            final Function<String, RefreshableAccessTokenHolder> refresher, final Supplier<RefreshableAccessTokenHolder> obtainer)
    {
        this.token = token;
        this.minimumTimeToLive = minimumTimeToLive;
        this.refresher = refresher;
        this.obtainer = obtainer;
    }

    @Override
    public String getAccessToken()
    {
        String validToken = null;

        this.tokenLock.readLock().lock();
        try
        {
            if (this.token != null && this.token.isActive()
                    && (!this.token.canRefresh() || !this.token.shouldRefresh(this.minimumTimeToLive)))
            {
                validToken = this.token.getToken();
            }
        }
        finally
        {
            this.tokenLock.readLock().unlock();
        }

        if (validToken == null)
        {
            this.tokenLock.writeLock().lock();
            try
            {
                if (this.token != null && this.token.isActive()
                        && (!this.token.canRefresh() || !this.token.shouldRefresh(this.minimumTimeToLive)))
                {
                    validToken = this.token.getToken();
                }

                if (validToken == null)
                {
                    if (this.token != null && this.token.canRefresh())
                    {
                        this.token = this.refresher.apply(this.token.getRefreshToken());
                    }
                    else if (this.obtainer != null)
                    {
                        this.token = this.obtainer.get();
                    }
                    else
                    {
                        throw new AccessTokenRefreshException(
                                "The way this access token was originally obtained does not allow to re-obtain it after expiration of the token and its associated refresh token");
                    }

                    validToken = this.token.getToken();
                }
            }
            finally
            {
                this.tokenLock.writeLock().unlock();
            }
        }

        return validToken;
    }
}
