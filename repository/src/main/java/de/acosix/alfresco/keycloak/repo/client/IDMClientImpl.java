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
package de.acosix.alfresco.keycloak.repo.client;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.MappingIterator;

import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Consumer;

import org.alfresco.error.AlfrescoRuntimeException;
import org.alfresco.repo.content.MimetypeMap;
import org.alfresco.util.ParameterCheck;
import org.alfresco.util.PropertyCheck;
import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.util.EntityUtils;
import org.keycloak.adapters.KeycloakDeployment;
import org.keycloak.common.util.KeycloakUriBuilder;
import org.keycloak.representations.idm.ClientRepresentation;
import org.keycloak.representations.idm.GroupRepresentation;
import org.keycloak.representations.idm.RoleRepresentation;
import org.keycloak.representations.idm.UserRepresentation;
import org.keycloak.util.JsonSerialization;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.InitializingBean;

import de.acosix.alfresco.keycloak.repo.token.AccessTokenHolder;
import de.acosix.alfresco.keycloak.repo.token.AccessTokenService;

/**
 * Implements the API for a client to the Keycloak admin ReST API specific to IDM structures.
 *
 * @author Axel Faust
 */
public class IDMClientImpl implements InitializingBean, IDMClient
{

    private static final Logger LOGGER = LoggerFactory.getLogger(IDMClientImpl.class);

    protected KeycloakDeployment deployment;

    protected AccessTokenService accessTokenService;

    protected String userName;

    protected String password;

    protected AccessTokenHolder accessToken;

    /**
     * {@inheritDoc}
     */
    @Override
    public void afterPropertiesSet()
    {
        PropertyCheck.mandatory(this, "keycloakDeployment", this.deployment);
        PropertyCheck.mandatory(this, "accessTokenService", this.accessTokenService);
    }

    /**
     * @param deployment
     *            the deployment to set
     */
    public void setDeployment(final KeycloakDeployment deployment)
    {
        this.deployment = deployment;
    }

    /**
     * @param accessTokenService
     *            the accessTokenService to set
     */
    public void setAccessTokenService(final AccessTokenService accessTokenService)
    {
        this.accessTokenService = accessTokenService;
    }

    /**
     * @param userName
     *            the userName to set
     */
    public void setUserName(final String userName)
    {
        this.userName = userName;
    }

    /**
     * @param password
     *            the password to set
     */
    public void setPassword(final String password)
    {
        this.password = password;
    }

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

        final GroupRepresentation group = this.processGenericGet(uri, GroupRepresentation.class);
        return group;
    }

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

        final int processedClients = this.processEntityBatch(uri, clientProcessor, ClientRepresentation.class);
        return processedClients;
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

        final int processedUsers = this.processEntityBatch(uri, userProcessor, UserRepresentation.class);
        return processedUsers;
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

        final int processedGroups = this.processEntityBatch(uri, groupProcessor, GroupRepresentation.class);
        return processedGroups;
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
                .queryParam("first", offset).queryParam("max", groupBatchSize).build(this.deployment.getRealm());

        if (offset < 0)
        {
            throw new IllegalArgumentException("offset must be a non-negative integer");
        }
        if (groupBatchSize <= 0)
        {
            throw new IllegalArgumentException("groupBatchSize must be a positive integer");
        }

        final int processedGroups = this.processEntityBatch(uri, groupProcessor, GroupRepresentation.class);
        return processedGroups;
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

        final int processedUsers = this.processEntityBatch(uri, userProcessor, UserRepresentation.class);
        return processedUsers;
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

        final int processedRoles = this.processEntityBatch(uri, roleProcessor, RoleRepresentation.class);
        return processedRoles;
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

        final int processedRoles = this.processEntityBatch(uri, roleProcessor, RoleRepresentation.class);
        return processedRoles;
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

        final int processedRoles = this.processEntityBatch(uri, roleProcessor, RoleRepresentation.class);
        return processedRoles;
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

        final int processedRoles = this.processEntityBatch(uri, roleProcessor, RoleRepresentation.class);
        return processedRoles;
    }

    /**
     * Loads and processes a batch of generic entities from Keycloak.
     *
     * @param <T>
     *            the type of the response entities
     * @param uri
     *            the URI to call
     * @param entityProcessor
     *            the processor handling the loaded entities
     * @param entityClass
     *            the type of the expected response entities
     * @return the number of processed entities
     */
    protected <T> int processEntityBatch(final URI uri, final Consumer<T> entityProcessor, final Class<T> entityClass)
    {
        final HttpGet get = new HttpGet(uri);
        get.addHeader("Accept", MimetypeMap.MIMETYPE_JSON);
        get.addHeader("Authorization", "Bearer " + this.getValidAccessTokenForRequest());

        try
        {
            final HttpClient client = this.deployment.getClient();
            final HttpResponse response = client.execute(get);

            final int status = response.getStatusLine().getStatusCode();
            final HttpEntity httpEntity = response.getEntity();
            if (status != 200)
            {
                EntityUtils.consumeQuietly(httpEntity);
                throw new IOException("Bad status: " + status);
            }
            if (httpEntity == null)
            {
                throw new IOException("Response does not contain a body");
            }

            final InputStream is = httpEntity.getContent();
            try
            {
                final MappingIterator<T> iterator = JsonSerialization.mapper.readerFor(entityClass).readValues(is);

                int entitiesProcessed = 0;
                while (iterator.hasNextValue())
                {
                    final T loadedEntity = iterator.nextValue();
                    entityProcessor.accept(loadedEntity);
                    entitiesProcessed++;
                }
                return entitiesProcessed;
            }
            finally
            {
                try
                {
                    is.close();
                }
                catch (final IOException e)
                {
                    LOGGER.trace("Error closing entity stream", e);
                }
            }
        }
        catch (final IOException ioex)
        {
            LOGGER.error("Failed to retrieve entities", ioex);
            throw new AlfrescoRuntimeException("Failed to retrieve entities", ioex);
        }
    }

    /**
     * Executes a generic HTTP GET operation yielding a JSON response.
     *
     * @param uri
     *            the URI to call
     * @param responseProcessor
     *            the processor handling the response JSON
     */
    protected void processGenericGet(final URI uri, final Consumer<JsonNode> responseProcessor)
    {
        final HttpGet get = new HttpGet(uri);
        get.addHeader("Accept", MimetypeMap.MIMETYPE_JSON);
        get.addHeader("Authorization", "Bearer " + this.getValidAccessTokenForRequest());

        try
        {
            final HttpClient client = this.deployment.getClient();
            final HttpResponse response = client.execute(get);

            final int status = response.getStatusLine().getStatusCode();
            final HttpEntity httpEntity = response.getEntity();
            if (status != 200)
            {
                EntityUtils.consumeQuietly(httpEntity);
                throw new IOException("Bad status: " + status);
            }
            if (httpEntity == null)
            {
                throw new IOException("Response does not contain a body");
            }

            final InputStream is = httpEntity.getContent();
            try
            {
                final JsonNode root = JsonSerialization.mapper.readTree(is);
                responseProcessor.accept(root);
            }
            finally
            {
                try
                {
                    is.close();
                }
                catch (final IOException e)
                {
                    LOGGER.trace("Error closing entity stream", e);
                }
            }
        }
        catch (final IOException ioex)
        {
            LOGGER.error("Failed to retrieve entities", ioex);
            throw new AlfrescoRuntimeException("Failed to retrieve entities", ioex);
        }
    }

    /**
     * Executes a generic HTTP GET operation yielding a mapped response entity.
     *
     * @param <T>
     *            the type of the response entity
     * @param uri
     *            the URI to call
     * @param responseType
     *            the class object for the type of the response entity
     * @return the response entity
     *
     */
    protected <T> T processGenericGet(final URI uri, final Class<T> responseType)
    {
        final HttpGet get = new HttpGet(uri);
        get.addHeader("Accept", MimetypeMap.MIMETYPE_JSON);
        get.addHeader("Authorization", "Bearer " + this.getValidAccessTokenForRequest());

        try
        {
            final HttpClient client = this.deployment.getClient();
            final HttpResponse response = client.execute(get);

            final int status = response.getStatusLine().getStatusCode();
            final HttpEntity httpEntity = response.getEntity();
            if (status != 200)
            {
                EntityUtils.consumeQuietly(httpEntity);
                throw new IOException("Bad status: " + status);
            }
            if (httpEntity == null)
            {
                throw new IOException("Response does not contain a body");
            }

            final InputStream is = httpEntity.getContent();
            try
            {
                final T responseEntity = JsonSerialization.mapper.readValue(is, responseType);
                return responseEntity;
            }
            finally
            {
                try
                {
                    is.close();
                }
                catch (final IOException e)
                {
                    LOGGER.trace("Error closing entity stream", e);
                }
            }
        }
        catch (final IOException ioex)
        {
            LOGGER.error("Failed to retrieve entities", ioex);
            throw new AlfrescoRuntimeException("Failed to retrieve entities", ioex);
        }
    }

    /**
     * Retrieves / determines a valid access token for a request to the admin ReST API.
     *
     * @return the valid access token to use in a request immediately following this operation
     */
    protected String getValidAccessTokenForRequest()
    {
        if (this.accessToken == null)
        {
            synchronized (this)
            {
                if (this.accessToken == null)
                {
                    if (this.userName != null && !this.userName.isEmpty())
                    {
                        this.accessToken = this.accessTokenService.obtainAccessToken(this.userName, this.password);
                    }
                    else
                    {
                        this.accessToken = this.accessTokenService.obtainAccessToken();
                    }
                }
            }
        }

        return this.accessToken.getAccessToken();
    }
}
