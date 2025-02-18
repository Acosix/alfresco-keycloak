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
package de.acosix.alfresco.keycloak.repo.client;

import java.util.function.Consumer;

import org.keycloak.representations.idm.ClientRepresentation;
import org.keycloak.representations.idm.RoleRepresentation;

/**
 * Instances of this interface wrap the relevant Keycloak admin ReST API for the synchronisation of roles from a Keycloak realm.
 *
 * @author Axel Faust
 */
public interface RolesClient
{

    /**
     * Loads and processes the registered clients from Keycloak using an externally specified processor.
     *
     * @param clientProcessor
     *     the processor handling the loaded clients
     * @return the number of processed clients
     */
    int processClients(Consumer<ClientRepresentation> clientProcessor);

    /**
     * Loads and processes a batch of realm roles from Keycloak using an externally specified processor.
     *
     * @param offset
     *     the index of the first role to retrieve
     * @param roleBatchSize
     *     the number of roles to load in one batch
     * @param roleProcessor
     *     the processor handling the loaded roles
     * @return the number of processed roles
     */
    int processRealmRoles(int offset, int roleBatchSize, Consumer<RoleRepresentation> roleProcessor);

    /**
     * Loads and processes a batch of realm roles from Keycloak using an externally specified processor.
     *
     * @param search
     *     a search term to filter roles
     * @param offset
     *     the index of the first role to retrieve
     * @param roleBatchSize
     *     the number of roles to load in one batch
     * @param roleProcessor
     *     the processor handling the loaded roles
     * @return the number of processed roles
     */
    int processRealmRoles(String search, int offset, int roleBatchSize, Consumer<RoleRepresentation> roleProcessor);

    /**
     * Loads and processes a batch of client roles from Keycloak using an externally specified processor.
     *
     * @param clientId
     *     the {@link ClientRepresentation#getId() (technical) ID} of a client from which to process defined roles
     * @param offset
     *     the index of the first role to retrieve
     * @param roleBatchSize
     *     the number of roles to load in one batch
     * @param roleProcessor
     *     the processor handling the loaded roles
     * @return the number of processed roles
     */
    int processClientRoles(String clientId, int offset, int roleBatchSize, Consumer<RoleRepresentation> roleProcessor);

    /**
     * Loads and processes a batch of client roles from Keycloak using an externally specified processor.
     *
     * @param clientId
     *     the {@link ClientRepresentation#getId() (technical) ID} of a client from which to process defined roles
     * @param search
     *     a search term to filter roles
     * @param offset
     *     the index of the first role to retrieve
     * @param roleBatchSize
     *     the number of roles to load in one batch
     * @param roleProcessor
     *     the processor handling the loaded roles
     * @return the number of processed roles
     */
    int processClientRoles(String clientId, String search, int offset, int roleBatchSize, Consumer<RoleRepresentation> roleProcessor);
}
