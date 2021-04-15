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
package de.acosix.alfresco.keycloak.repo.sync;

import org.alfresco.repo.security.sync.NodeDescription;
import org.keycloak.representations.idm.GroupRepresentation;

/**
 * Instances of this interface are to map data from Keycloak groups to the Alfresco authority container node description. All instances of
 * this interface in the Keycloak authentication subsystem will be consulted in the order the beans are defined in the Spring application
 * context, resulting in an aggregated authority container node description.
 *
 * @author Axel Faust
 */
public interface GroupProcessor
{

    /**
     * Maps data from a Keycloak group representation to a description of an Alfresco node for the authority container.
     *
     * @param group
     *            the Keycloak group representation
     * @param groupNodeDescription
     *            the Alfresco node description
     */
    void mapGroup(GroupRepresentation group, NodeDescription groupNodeDescription);
}
