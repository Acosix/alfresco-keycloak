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

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.MappingIterator;

import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashSet;
import java.util.function.Consumer;

import org.alfresco.error.AlfrescoRuntimeException;
import org.alfresco.repo.content.MimetypeMap;
import org.alfresco.util.PropertyCheck;
import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.util.EntityUtils;
import org.keycloak.adapters.KeycloakDeployment;
import org.keycloak.util.JsonSerialization;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.InitializingBean;

import de.acosix.alfresco.keycloak.repo.token.AccessTokenHolder;
import de.acosix.alfresco.keycloak.repo.token.AccessTokenService;

/**
 * Implements the abstract base for a client to the Keycloak admin ReST API specific to IDM structures.
 *
 * @author Axel Faust
 */
public abstract class AbstractIDMClientImpl implements InitializingBean
{

    private static final Logger LOGGER = LoggerFactory.getLogger(AbstractIDMClientImpl.class);

    static
    {
        // newer Keycloak versions may introduce properties the libraries included in this project do not support
        JsonSerialization.mapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
    }

    protected KeycloakDeployment deployment;

    protected AccessTokenService accessTokenService;

    protected String userName;

    protected String password;

    protected final Collection<String> requiredClientScopes = new HashSet<>();

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
     *     the deployment to set
     */
    public void setDeployment(final KeycloakDeployment deployment)
    {
        this.deployment = deployment;
    }

    /**
     * @param accessTokenService
     *     the accessTokenService to set
     */
    public void setAccessTokenService(final AccessTokenService accessTokenService)
    {
        this.accessTokenService = accessTokenService;
    }

    /**
     * @param userName
     *     the userName to set
     */
    public void setUserName(final String userName)
    {
        this.userName = userName;
    }

    /**
     * @param password
     *     the password to set
     */
    public void setPassword(final String password)
    {
        this.password = password;
    }

    /**
     * @param requiredClientScopes
     *     the requiredClientScopes to set
     */
    public void setRequiredClientScopes(final String requiredClientScopes)
    {
        this.requiredClientScopes.clear();
        if (requiredClientScopes != null && !requiredClientScopes.isEmpty())
        {
            this.requiredClientScopes.addAll(Arrays.asList(requiredClientScopes.trim().split(" ")));
        }
    }

    /**
     * Loads and processes a batch of generic entities from Keycloak.
     *
     * @param <T>
     *     the type of the response entities
     * @param uri
     *     the URI to call
     * @param entityProcessor
     *     the processor handling the loaded entities
     * @param entityClass
     *     the type of the expected response entities
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
     *     the URI to call
     * @param responseProcessor
     *     the processor handling the response JSON
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
     *     the type of the response entity
     * @param uri
     *     the URI to call
     * @param responseType
     *     the class object for the type of the response entity
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
                        this.accessToken = this.accessTokenService.obtainAccessToken(this.userName, this.password,
                                this.requiredClientScopes);
                    }
                    else
                    {
                        this.accessToken = this.accessTokenService.obtainAccessToken(this.requiredClientScopes);
                    }
                }
            }
        }

        return this.accessToken.getAccessToken();
    }
}
