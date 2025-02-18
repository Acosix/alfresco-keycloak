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

import java.net.URI;
import java.util.function.Consumer;

import org.alfresco.util.ParameterCheck;
import org.keycloak.common.util.KeycloakUriBuilder;
import org.keycloak.representations.idm.ClientRepresentation;
import org.keycloak.representations.idm.RoleRepresentation;

/**
 * Implements the API for a client to the Keycloak admin ReST API specific to roles.
 *
 * @author Axel Faust
 */
public class RolesClientImpl extends AbstractIDMClientImpl implements RolesClient
{

    /**
     *
     * {@inheritDoc}
     */
    @Override
    public int processClients(final Consumer<ClientRepresentation> clientProcessor)
    {
        ParameterCheck.mandatory("clientProcessor", clientProcessor);

        final URI uri = KeycloakUriBuilder.fromUri(this.deployment.getAuthServerBaseUrl()).path("/admin/realms/{realm}/clients")
                .build(this.deployment.getRealm());

        return this.processEntityBatch(uri, clientProcessor, ClientRepresentation.class);
    }

    /**
     *
     * {@inheritDoc}
     */
    @Override
    public int processRealmRoles(final int offset, final int userBatchSize, final Consumer<RoleRepresentation> roleProcessor)
    {
        ParameterCheck.mandatory("roleProcessor", roleProcessor);

        if (offset < 0)
        {
            throw new IllegalArgumentException("offset must be a non-negative integer");
        }
        if (userBatchSize <= 0)
        {
            throw new IllegalArgumentException("userBatchSize must be a positive integer");
        }

        final URI uri = KeycloakUriBuilder.fromUri(this.deployment.getAuthServerBaseUrl()).path("/admin/realms/{realm}/roles")
                .queryParam("first", offset).queryParam("max", userBatchSize).build(this.deployment.getRealm());

        return this.processEntityBatch(uri, roleProcessor, RoleRepresentation.class);
    }

    /**
     *
     * {@inheritDoc}
     */
    @Override
    public int processRealmRoles(final String search, final int offset, final int userBatchSize,
            final Consumer<RoleRepresentation> roleProcessor)
    {
        ParameterCheck.mandatory("roleProcessor", roleProcessor);
        ParameterCheck.mandatoryString("search", search);

        if (offset < 0)
        {
            throw new IllegalArgumentException("offset must be a non-negative integer");
        }
        if (userBatchSize <= 0)
        {
            throw new IllegalArgumentException("userBatchSize must be a positive integer");
        }

        final URI uri = KeycloakUriBuilder.fromUri(this.deployment.getAuthServerBaseUrl()).path("/admin/realms/{realm}/roles")
                .queryParam("first", offset).queryParam("max", userBatchSize).queryParam("search", search)
                .build(this.deployment.getRealm());

        return this.processEntityBatch(uri, roleProcessor, RoleRepresentation.class);
    }

    /**
     *
     * {@inheritDoc}
     */
    @Override
    public int processClientRoles(final String clientId, final int offset, final int userBatchSize,
            final Consumer<RoleRepresentation> roleProcessor)
    {
        ParameterCheck.mandatoryString("clientId", clientId);
        ParameterCheck.mandatory("roleProcessor", roleProcessor);

        if (offset < 0)
        {
            throw new IllegalArgumentException("offset must be a non-negative integer");
        }
        if (userBatchSize <= 0)
        {
            throw new IllegalArgumentException("userBatchSize must be a positive integer");
        }

        final URI uri = KeycloakUriBuilder.fromUri(this.deployment.getAuthServerBaseUrl())
                .path("/admin/realms/{realm}/clients/{clientId}/roles").queryParam("first", offset).queryParam("max", userBatchSize)
                .build(this.deployment.getRealm(), clientId);

        return this.processEntityBatch(uri, roleProcessor, RoleRepresentation.class);
    }

    /**
     *
     * {@inheritDoc}
     */
    @Override
    public int processClientRoles(final String clientId, final String search, final int offset, final int userBatchSize,
            final Consumer<RoleRepresentation> roleProcessor)
    {
        ParameterCheck.mandatoryString("clientId", clientId);
        ParameterCheck.mandatoryString("search", search);
        ParameterCheck.mandatory("roleProcessor", roleProcessor);

        if (offset < 0)
        {
            throw new IllegalArgumentException("offset must be a non-negative integer");
        }
        if (userBatchSize <= 0)
        {
            throw new IllegalArgumentException("userBatchSize must be a positive integer");
        }

        final URI uri = KeycloakUriBuilder.fromUri(this.deployment.getAuthServerBaseUrl())
                .path("/admin/realms/{realm}/clients/{clientId}/roles").queryParam("first", offset).queryParam("max", userBatchSize)
                .queryParam("search", search).build(this.deployment.getRealm(), clientId);

        return this.processEntityBatch(uri, roleProcessor, RoleRepresentation.class);
    }
}
