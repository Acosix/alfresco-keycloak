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
package de.acosix.alfresco.keycloak.repo.roles;

/**
 * Instances of this interface test the name of a Keycloak role for potential inclusion in Alfresco authority / ACL operations.
 *
 * @author Axel Faust
 */
public interface RoleNameFilter
{

    /**
     * Checks whether a specific role should be exposed to Alfresco authority / ACL operations.
     *
     * @param roleName
     *            the name of the role
     * @return {@code true} if the role should be exposed, {@code false} if it should be ignored
     */
    boolean isRoleExposed(String roleName);
}
