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

/**
 * This no-op implementation class of an access token service may be used as a default implemenation in a subsystem proxy to avoid failing
 * if no Keycloak subsystem instance is active.
 *
 * @author Axel Faust
 */
public class NoOpAccessTokenServiceImpl implements AccessTokenService
{

    private static final String UNSUPPORTED_MESSAGE = "A Keycloak subsystem is not configured / enabled";

    /**
     *
     * {@inheritDoc}
     */
    @Override
    public AccessTokenHolder obtainAccessToken(final Collection<String> scopes)
    {
        throw new AccessTokenUnsupportedException(UNSUPPORTED_MESSAGE);
    }

    /**
     *
     * {@inheritDoc}
     */
    @Override
    public AccessTokenHolder obtainAccessToken(final String user, final String password, final Collection<String> scopes)
    {
        throw new AccessTokenUnsupportedException(UNSUPPORTED_MESSAGE);
    }

    /**
     *
     * {@inheritDoc}
     */
    @Override
    public AccessTokenHolder exchangeToken(final String accessToken, final String client, final Collection<String> scopes)
    {
        throw new AccessTokenUnsupportedException(UNSUPPORTED_MESSAGE);
    }

}
