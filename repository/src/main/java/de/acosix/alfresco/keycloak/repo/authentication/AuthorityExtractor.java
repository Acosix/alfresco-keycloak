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

import java.util.Set;

import org.alfresco.service.cmr.security.AuthorityService;
import org.alfresco.service.cmr.security.AuthorityType;
import org.keycloak.representations.AccessToken;

/**
 * Instances of this interface are used to map / extract authorities for an authenticated user from Keycloak authenticated users for use as
 * {@link AuthorityService#getAuthorities() authorities of the current user}. Any mapped / extracted authority will be considered to be an
 * authority of the user without the need of any explicit authority membership in the node structures of Alfresco - such authorities are
 * typically used as global roles.
 *
 * @author Axel Faust
 */
public interface AuthorityExtractor
{

    /**
     * Maps / extracts authorities from a Keycloak access token.
     *
     * @param accessToken
     *            the Keycloak access token for the authenticated user
     * @return the mapped / extracted authorities - never {@code null} and authorities must already include the appropriate prefix for the
     *         {@link AuthorityType authority type} as which they should be treated
     */
    Set<String> extractAuthorities(AccessToken accessToken);
}
