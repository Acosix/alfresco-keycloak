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
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Consumer;

import org.alfresco.error.AlfrescoRuntimeException;
import org.alfresco.util.ParameterCheck;
import org.keycloak.common.util.KeycloakUriBuilder;
import org.keycloak.representations.idm.GroupRepresentation;
import org.keycloak.representations.idm.UserRepresentation;

/**
 * Implements the API for a client to the Keycloak admin ReST API specific to users and groups.
 *
 * @author Axel Faust
 */
public class IdentitiesClientImpl extends AbstractIDMClientImpl implements IdentitiesClient
{

    /**
     *
     * {@inheritDoc}
     */
    @Override
    public int countUsers()
    {
        final URI uri = KeycloakUriBuilder.fromUri(this.deployment.getAuthServerBaseUrl()).path("/admin/realms/{realm}/users/count")
                .build(this.deployment.getRealm());

        final AtomicInteger count = new AtomicInteger(0);
        this.processGenericGet(uri, root -> {
            if (root.isInt())
            {
                count.set(root.intValue());
            }
            else
            {
                throw new AlfrescoRuntimeException("Keycloak admin API did not yield expected data for user count");
            }
        });

        return count.get();
    }

    /**
     *
     * {@inheritDoc}
     */
    @Override
    public int countGroups()
    {
        final URI uri = KeycloakUriBuilder.fromUri(this.deployment.getAuthServerBaseUrl()).path("/admin/realms/{realm}/groups/count")
                .build(this.deployment.getRealm());

        final AtomicInteger count = new AtomicInteger(0);
        this.processGenericGet(uri, root -> {
            if (root.isObject() && root.has("count"))
            {
                count.set(root.get("count").intValue());
            }
            else
            {
                throw new AlfrescoRuntimeException("Keycloak admin API did not yield expected JSON data for group count");
            }
        });

        return count.get();
    }

    /**
     *
     * {@inheritDoc}
     */
    @Override
    public GroupRepresentation getGroup(final String groupId)
    {
        ParameterCheck.mandatoryString("groupId", groupId);

        final URI uri = KeycloakUriBuilder.fromUri(this.deployment.getAuthServerBaseUrl()).path("/admin/realms/{realm}/groups/{groupId}")
                .build(this.deployment.getRealm(), groupId);

        return this.processGenericGet(uri, GroupRepresentation.class);
    }

    /**
     *
     * {@inheritDoc}
     */
    @Override
    public int processUsers(final int offset, final int userBatchSize, final Consumer<UserRepresentation> userProcessor)
    {
        ParameterCheck.mandatory("userProcessor", userProcessor);

        if (offset < 0)
        {
            throw new IllegalArgumentException("offset must be a non-negative integer");
        }
        if (userBatchSize <= 0)
        {
            throw new IllegalArgumentException("userBatchSize must be a positive integer");
        }

        final URI uri = KeycloakUriBuilder.fromUri(this.deployment.getAuthServerBaseUrl()).path("/admin/realms/{realm}/users")
                .queryParam("first", offset).queryParam("max", userBatchSize).build(this.deployment.getRealm());

        return this.processEntityBatch(uri, userProcessor, UserRepresentation.class);
    }

    /**
     *
     * {@inheritDoc}
     */
    @Override
    public int processUserGroups(final String userId, final int offset, final int groupBatchSize,
            final Consumer<GroupRepresentation> groupProcessor)
    {
        ParameterCheck.mandatoryString("userId", userId);
        ParameterCheck.mandatory("groupProcessor", groupProcessor);

        final URI uri = KeycloakUriBuilder.fromUri(this.deployment.getAuthServerBaseUrl()).path("/admin/realms/{realm}/users/{user}/groups")
                .queryParam("first", offset).queryParam("max", groupBatchSize).build(this.deployment.getRealm(), userId);

        if (offset < 0)
        {
            throw new IllegalArgumentException("offset must be a non-negative integer");
        }
        if (groupBatchSize <= 0)
        {
            throw new IllegalArgumentException("groupBatchSize must be a positive integer");
        }

        return this.processEntityBatch(uri, groupProcessor, GroupRepresentation.class);
    }

    /**
     *
     * {@inheritDoc}
     */
    @Override
    public int processGroups(final int offset, final int groupBatchSize, final Consumer<GroupRepresentation> groupProcessor)
    {
        ParameterCheck.mandatory("groupProcessor", groupProcessor);

        final URI uri = KeycloakUriBuilder.fromUri(this.deployment.getAuthServerBaseUrl()).path("/admin/realms/{realm}/groups")
                .queryParam("first", offset).queryParam("max", groupBatchSize).queryParam("briefRepresentation", false)
                .build(this.deployment.getRealm());

        if (offset < 0)
        {
            throw new IllegalArgumentException("offset must be a non-negative integer");
        }
        if (groupBatchSize <= 0)
        {
            throw new IllegalArgumentException("groupBatchSize must be a positive integer");
        }

        return this.processEntityBatch(uri, groupProcessor, GroupRepresentation.class);
    }

    /**
     *
     * {@inheritDoc}
     */
    @Override
    public int processSubGroups(final String groupId, final Consumer<GroupRepresentation> groupProcessor)
    {
        ParameterCheck.mandatoryString("groupId", groupId);
        ParameterCheck.mandatory("groupProcessor", groupProcessor);

        final URI uri = KeycloakUriBuilder.fromUri(this.deployment.getAuthServerBaseUrl())
                .path("/admin/realms/{realm}/groups/{groupId}/children").substitutePathParam("groupId", groupId, false)
                .queryParam("briefRepresentation", false).build(this.deployment.getRealm());

        return this.processEntityBatch(uri, groupProcessor, GroupRepresentation.class);
    }

    /**
     *
     * {@inheritDoc}
     */
    @Override
    public int processMembers(final String groupId, final int offset, final int userBatchSize,
            final Consumer<UserRepresentation> userProcessor)
    {
        ParameterCheck.mandatoryString("groupId", groupId);
        ParameterCheck.mandatory("userProcessor", userProcessor);

        if (offset < 0)
        {
            throw new IllegalArgumentException("offset must be a non-negative integer");
        }
        if (userBatchSize <= 0)
        {
            throw new IllegalArgumentException("userBatchSize must be a positive integer");
        }

        final URI uri = KeycloakUriBuilder.fromUri(this.deployment.getAuthServerBaseUrl())
                .path("/admin/realms/{realm}/groups/{groupId}/members").queryParam("first", offset).queryParam("max", userBatchSize)
                .build(this.deployment.getRealm(), groupId);

        return this.processEntityBatch(uri, userProcessor, UserRepresentation.class);
    }
}
