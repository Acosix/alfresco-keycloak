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
package de.acosix.alfresco.keycloak.repo.sync;

import org.keycloak.representations.idm.GroupRepresentation;

/**
 * Instances of this interface are used to determine which groups should be synchronised. All instances of this interface in the Keycloak
 * authentication subsystem will be consulted and only groups for which every filter returns {@code true} will be synchronised. If no filter
 * instances have been defined, groups will always be synchronised without any filtering.
 *
 * @author Axel Faust
 */
public interface GroupFilter
{

    /**
     * Determines whether this group should be included in the synchronisation.
     *
     * @param group
     *     the group to consider
     * @return the filter result
     */
    FilterResult shouldIncludeGroup(GroupRepresentation group);
}
