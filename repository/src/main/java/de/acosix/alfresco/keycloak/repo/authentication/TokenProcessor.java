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

import org.keycloak.representations.AccessToken;
import org.keycloak.representations.IDToken;

/**
 * Instances of this interface are used to process access tokens from Keycloak authenticated users. All instances of this
 * interface in the Keycloak authentication subsystem will be consulted in the order defined by the {@link #getPriority() priority} or the
 * order the beans are defined in the Spring application context in case of identical priorities.
 *
 * @author Brian Long
 */
public interface TokenProcessor extends Comparable<TokenProcessor>
{

    /**
     * The default priority value of a token processor if {@link #getPriority() getPriority} is not overridden.
     */
    int DEFAULT_PRIORITY = 0;

    /**
     * Retrieves the name of this processor, typically for logging and reference purposes.
     *
     * @return the name of this processor
     */
    String getName();

    /**
     * A priority for sorting beans for execution order.
     *
     * @return the priority - the lower the earlier this bean is processed
     */
    default int getPriority()
    {
        return DEFAULT_PRIORITY;
    }

    /**
     * Handles access tokens from Keycloak.
     *
     * @param accessToken
     *     the Keycloak access token for the authenticated user
     * @param idToken
     *     the Keycloak ID token for the authenticated user - may be {@code null} if not contained in the authentication response
     * @param freshLogin
     *     {@code true} if the tokens are fresh, that is have just been obtained from an initial login, {@code false} otherwise
     */
    void handleUserTokens(AccessToken accessToken, IDToken idToken, boolean freshLogin);

    /**
     *
     * {@inheritDoc}
     */
    @Override
    default int compareTo(final TokenProcessor o)
    {
        return Integer.compare(this.getPriority(), o.getPriority());
    }

}
