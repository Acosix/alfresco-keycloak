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

import java.util.Optional;

import org.alfresco.repo.security.sync.NodeDescription;
import org.keycloak.representations.idm.GroupRepresentation;

/**
 * Instances of this interface are to map data from Keycloak groups to the Alfresco authority container node description. All instances of
 * this interface in the Keycloak authentication subsystem will be consulted in the order the beans are defined in the Spring application
 * context, resulting in an aggregated authority container node description.
 *
 * @author Axel Faust
 */
public interface GroupProcessor extends Comparable<GroupProcessor>
{

    /**
     * Retrieves the priority of this processor. A lower value specifies a higher priority and the mapped properties / group name of
     * processors with higher priorities may override those of lower priorities.
     *
     * @return the priority as an integer with {@code 50} as the default priority.
     */
    default int getPriority()
    {
        return 50;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    default int compareTo(final GroupProcessor other)
    {
        int res = Integer.compare(this.getPriority(), other.getPriority());
        if (res == 0)
        {
            res = this.getClass().getName().compareTo(other.getClass().getName());
        }
        return res;
    }

    /**
     * Maps data from a Keycloak group representation to a description of an Alfresco node for the authority container.
     *
     * @param group
     *     the Keycloak group representation
     * @param groupNodeDescription
     *     the Alfresco node description
     */
    void mapGroup(GroupRepresentation group, NodeDescription groupNodeDescription);

    /**
     * Maps a Keycloak group representation to the group name to use in Alfresco.
     *
     * @param group
     *     the Keycloak group representation
     * @return the Alfresco group name
     */
    default Optional<String> mapGroupName(final GroupRepresentation group)
    {
        return Optional.empty();
    }
}
