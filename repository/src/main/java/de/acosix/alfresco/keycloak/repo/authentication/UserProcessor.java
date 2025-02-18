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

import java.io.Serializable;
import java.util.Map;

import org.alfresco.service.namespace.QName;
import org.keycloak.representations.AccessToken;
import org.keycloak.representations.IDToken;

/**
 * Instances of this interface are used to map data from Keycloak authenticated users to the Alfresco person node. All instances of this
 * interface in the Keycloak authentication subsystem will be consulted in the order the beans are defined in the Spring application
 * context, resulting in an aggregated map of person node properties.
 *
 * @author Axel Faust
 */
public interface UserProcessor
{

    /**
     * Maps data from Keycloak access and ID tokens to a map of properties for the corresponding person node.
     *
     * @param accessToken
     *            the Keycloak access token for the authenticated user
     * @param idToken
     *            the Keycloak ID token for the authenticated user - may be {@code null} if not contained in the authentication response
     * @param personNodeProperties
     *            the properties to set on the Alfresco person node corresponding to the authenticated user
     */
    void mapUser(AccessToken accessToken, IDToken idToken, Map<QName, Serializable> personNodeProperties);
}
