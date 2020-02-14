/*
 * Copyright 2019 - 2020 Acosix GmbH
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
package de.acosix.alfresco.keycloak.repo.roles;

import java.util.List;

/**
 * Instances of this interface allow for lookup / retrieval of Keycloak roles.
 *
 * @author Axel Faust
 */
public interface RoleService
{

    /**
     * Finds matching roles in the main realm and/or resource scopes (as far as possible based on configuration).
     *
     * @param shortNameFilter
     *            name pattern on which to filter groups - the filter will be applied on both the original Keycloak and the mapped Alfresco
     *            role name, and a match in either will result the role to be considered a match
     * @return the list of matching roles
     */
    List<Role> findRoles(String shortNameFilter);

    /**
     * Finds matching roles in the main realm and/or resource scopes (as far as possible based on configuration).
     *
     * @param shortNameFilter
     *            name pattern on which to filter groups - the filter will be applied on both the original Keycloak and the mapped Alfresco
     *            role name, and a match in either will result the role to be considered a match
     * @param realmOnly
     *            {@code true} if the search operation should only consider the main realm, or {@code false} if both realm and resource
     *            scopes are allowed to be searched
     * @return the list of matching roles
     */
    List<Role> findRoles(String shortNameFilter, boolean realmOnly);

    /**
     * Finds matching roles in a specific resource scope (as far as possible based on configuration).
     *
     * @param resourceName
     *            the name of the resource for which to retrieve roles
     * @param shortNameFilter
     *            name pattern on which to filter groups - the filter will be applied on both the original Keycloak and the mapped Alfresco
     *            role name, and a match in either will result the role to be considered a match
     * @return the list of matching roles
     */
    List<Role> findRoles(String resourceName, String shortNameFilter);

}
