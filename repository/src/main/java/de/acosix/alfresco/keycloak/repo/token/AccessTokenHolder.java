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

/**
 * Instances of this interface act as holders of a specific access authentication, encapsulating functionality which may dynamically change
 * the value of the effective access token, such as automatic refresh and re-obtaining of the access token when necessary.
 *
 * @author Axel Faust
 */
public interface AccessTokenHolder
{

    /**
     * Retrieves the access token from this instance. The result of this operation must never be externally cached as this operation
     * transparently handles validation, potential refresh and re-obtaining of the underlying access token when necessary.
     *
     * @return the valid access token
     * @throws AccessTokenRefreshException
     *             if a necessary refresh of the access token fails or cannot not be performed due to the way the access token was
     *             originally obtained
     */
    String getAccessToken();

}
