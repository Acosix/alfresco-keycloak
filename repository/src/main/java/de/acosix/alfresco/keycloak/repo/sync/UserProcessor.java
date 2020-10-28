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
package de.acosix.alfresco.keycloak.repo.sync;

import java.util.Collection;

import org.alfresco.repo.security.sync.NodeDescription;
import org.alfresco.service.namespace.QName;
import org.keycloak.representations.idm.UserRepresentation;

/**
 * Instances of this interface are used to map data from Keycloak users to the Alfresco person node description. All instances of this
 * interface in the Keycloak authentication subsystem will be consulted in the order the beans are defined in the Spring application
 * context, resulting in an aggregated person node description.
 *
 * @author Axel Faust
 */
public interface UserProcessor
{

    /**
     * Maps data from a Keycloak user representation to a description of an Alfresco node for the person.
     *
     * @param user
     *            the Keycloak user representation
     * @param personNodeDescription
     *            the Alfresco node description
     */
    void mapUser(UserRepresentation user, NodeDescription personNodeDescription);

    /**
     * Retrieves the set of properties mapped by this instance.
     *
     * @return the set of person node properties mapped by this instance
     */
    Collection<QName> getMappedProperties();
}
