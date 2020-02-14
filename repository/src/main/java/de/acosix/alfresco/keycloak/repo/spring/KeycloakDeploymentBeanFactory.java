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
package de.acosix.alfresco.keycloak.repo.spring;

import java.net.InetAddress;
import java.util.concurrent.TimeUnit;

import org.alfresco.httpclient.HttpClientFactory.NonBlockingHttpParamsFactory;
import org.alfresco.util.PropertyCheck;
import org.apache.commons.httpclient.params.DefaultHttpParams;
import org.apache.http.HttpHost;
import org.apache.http.client.HttpClient;
import org.apache.http.conn.params.ConnRoutePNames;
import org.apache.http.conn.params.ConnRouteParams;
import org.apache.http.conn.routing.HttpRoute;
import org.apache.http.params.HttpParams;
import org.springframework.beans.factory.FactoryBean;
import org.springframework.beans.factory.InitializingBean;

import de.acosix.alfresco.keycloak.repo.deps.keycloak.adapters.HttpClientBuilder;
import de.acosix.alfresco.keycloak.repo.deps.keycloak.adapters.KeycloakDeployment;
import de.acosix.alfresco.keycloak.repo.deps.keycloak.adapters.KeycloakDeploymentBuilder;
import de.acosix.alfresco.keycloak.repo.deps.keycloak.representations.adapters.config.AdapterConfig;

/**
 * @author Axel Faust
 */
public class KeycloakDeploymentBeanFactory implements FactoryBean<KeycloakDeployment>, InitializingBean
{

    static
    {
        // use same Alfresco NonBlockingHttpParamsFactory as SolrQueryHTTPClient (indirectly) does
        DefaultHttpParams.setHttpParamsFactory(new NonBlockingHttpParamsFactory());
    }

    protected AdapterConfig adapterConfig;

    protected String directAuthHost;

    protected int connectionTimeout;

    protected int socketTimeout;

    /**
     *
     * {@inheritDoc}
     */
    @Override
    public void afterPropertiesSet()
    {
        PropertyCheck.mandatory(this, "adapterConfig", this.adapterConfig);
    }

    /**
     * @param adapterConfig
     *            the adapterConfig to set
     */
    public void setAdapterConfig(final AdapterConfig adapterConfig)
    {
        this.adapterConfig = adapterConfig;
    }

    /**
     * @param directAuthHost
     *            the directAuthHost to set
     */
    public void setDirectAuthHost(final String directAuthHost)
    {
        this.directAuthHost = directAuthHost;
    }

    /**
     * @param connectionTimeout
     *            the connectionTimeout to set
     */
    public void setConnectionTimeout(final int connectionTimeout)
    {
        this.connectionTimeout = connectionTimeout;
    }

    /**
     * @param socketTimeout
     *            the socketTimeout to set
     */
    public void setSocketTimeout(final int socketTimeout)
    {
        this.socketTimeout = socketTimeout;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public KeycloakDeployment getObject() throws Exception
    {
        final KeycloakDeployment keycloakDeployment = KeycloakDeploymentBuilder.build(this.adapterConfig);

        HttpClientBuilder httpClientBuilder = new HttpClientBuilder();
        if (this.connectionTimeout > 0)
        {
            httpClientBuilder = httpClientBuilder.establishConnectionTimeout(this.connectionTimeout, TimeUnit.MILLISECONDS);
        }
        if (this.socketTimeout > 0)
        {
            httpClientBuilder = httpClientBuilder.socketTimeout(this.socketTimeout, TimeUnit.MILLISECONDS);
        }

        final HttpClient client = httpClientBuilder.build(this.adapterConfig);
        this.configureForcedRouteIfNecessary(client);
        keycloakDeployment.setClient(client);

        return keycloakDeployment;
    }

    /**
     *
     * {@inheritDoc}
     */
    @Override
    public boolean isSingleton()
    {
        // individual components may need to modify its configuration for their specific use case
        // so this should not be a shared singleton
        return false;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Class<?> getObjectType()
    {
        return KeycloakDeployment.class;
    }

    @SuppressWarnings("deprecation")
    protected void configureForcedRouteIfNecessary(final HttpClient client)
    {
        if (this.directAuthHost != null && !this.directAuthHost.isEmpty())
        {
            final HttpHost directAuthHost = HttpHost.create(this.directAuthHost);
            final HttpParams params = client.getParams();
            final InetAddress local = ConnRouteParams.getLocalAddress(params);
            final HttpHost proxy = ConnRouteParams.getDefaultProxy(params);
            final boolean secure = directAuthHost.getSchemeName().equalsIgnoreCase("https");

            HttpRoute route;
            if (proxy == null)
            {
                route = new HttpRoute(directAuthHost, local, secure);
            }
            else
            {
                route = new HttpRoute(directAuthHost, local, proxy, secure);
            }
            params.setParameter(ConnRoutePNames.FORCED_ROUTE, route);
        }
    }
}