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
package de.acosix.alfresco.keycloak.repo.token;

/**
 * Instances of this interface allow for the retrieval of access tokens in the Keycloak realm to which this Alfresco instance is connected.
 *
 * @author Axel Faust
 */
public interface AccessTokenService
{

    /**
     * Obtains a generic realm access token for the specific client of this Alfresco instance.
     *
     * @return the holder for the access token
     * @throws IllegalStateException
     *             if no access token for the client can be obtained, e.g. if no service account for it has been configured in Keycloak
     */
    AccessTokenHolder obtainAccessToken();

    /**
     * Obtains a generic realm access token for a specific user of the realm.
     *
     * @param user
     *            the name of the user
     * @param password
     *            the password of the user
     * @return the holder for the access token
     * @throws IllegalStateException
     *             if no access token for the client can be obtained, e.g. if direct access grants have not been enabled for the specific
     *             client of this Alfresco instance
     */
    AccessTokenHolder obtainAccessToken(String user, String password);

    /**
     * Performs a token exchange operation to obtain an access token for a specific client, acting in the name / context of the user for
     * which the original access token was issued.
     *
     * @param accessToken
     *            the access token to exchange for token to another client
     * @param client
     *            the client for which to obtain an access token
     * @return the holder for the access token
     * @throws IllegalStateException
     *             if no access token for the client can be obtained, e.g. if no service account for it has been configured in Keycloak
     */
    AccessTokenHolder exchangeToken(String accessToken, String client);
}
