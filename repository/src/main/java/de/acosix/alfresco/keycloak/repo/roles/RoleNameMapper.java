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

import java.util.Optional;

import org.alfresco.service.cmr.security.AuthorityType;

/**
 * Instances of this interface map the name of a Keycloak role into an Alfresco authority name.
 *
 * @author Axel Faust
 */
public interface RoleNameMapper
{

    /**
     * Maps the name of a role.
     *
     * @param roleName
     *            the name of the role
     * @return the mapped Alfresco authority name - if the authority name does not start with either the {@link AuthorityType#ROLE ROLE_} or
     *         {@link AuthorityType#GROUP GROUP_} prefix, the {@link AuthorityType#ROLE ROLE_} will always be prefixed by clients of this
     *         operation
     */
    Optional<String> mapRoleName(String roleName);

    /**
     * Maps the name of an Alfresco authority to the name of a Keycloak role. This operation should act like the inverse of the
     * {@link #mapRoleName(String) original inbound mapping}.
     *
     * @param authorityName
     *            the Alfresco authority name
     * @return the name of the Keycloak role
     */
    Optional<String> mapAuthorityName(String authorityName);
}
