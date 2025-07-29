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
package de.acosix.alfresco.keycloak.repo.spring;

import java.net.InetAddress;

import org.alfresco.httpclient.HttpClientFactory.NonBlockingHttpParamsFactory;
import org.alfresco.util.PropertyCheck;
import org.apache.commons.httpclient.params.DefaultHttpParams;
import org.apache.http.HttpHost;
import org.apache.http.client.HttpClient;
import org.apache.http.conn.params.ConnRoutePNames;
import org.apache.http.conn.params.ConnRouteParams;
import org.apache.http.conn.routing.HttpRoute;
import org.apache.http.params.HttpParams;
import org.keycloak.adapters.HttpClientBuilder;
import org.keycloak.adapters.KeycloakDeployment;
import org.keycloak.adapters.KeycloakDeploymentBuilder;
import org.springframework.beans.factory.FactoryBean;
import org.springframework.beans.factory.InitializingBean;

/**
 * @author Axel Faust
 */
@SuppressWarnings("deprecation")
public class KeycloakDeploymentBeanFactory implements FactoryBean<KeycloakDeployment>, InitializingBean
{

    static
    {
        // use same Alfresco NonBlockingHttpParamsFactory as SolrQueryHTTPClient (indirectly) does
        DefaultHttpParams.setHttpParamsFactory(new NonBlockingHttpParamsFactory());
    }

    protected ExtendedAdapterConfig adapterConfig;

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
     *     the adapterConfig to set
     */
    public void setAdapterConfig(final ExtendedAdapterConfig adapterConfig)
    {
        this.adapterConfig = adapterConfig;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public KeycloakDeployment getObject() throws Exception
    {
        final KeycloakDeployment keycloakDeployment = KeycloakDeploymentBuilder.build(this.adapterConfig);
        final HttpClientBuilder httpClientBuilder = new HttpClientBuilder();
        final HttpClient client = httpClientBuilder.build(this.adapterConfig);
        this.configureForcedRouteIfNecessary(client, this.adapterConfig.getForcedRouteUrl());
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

    protected void configureForcedRouteIfNecessary(final HttpClient client, final String forcedRoute)
    {
        if (forcedRoute != null && !forcedRoute.isEmpty())
        {
            final HttpHost forcedRouteHost = HttpHost.create(forcedRoute);
            final HttpParams params = client.getParams();
            final InetAddress local = ConnRouteParams.getLocalAddress(params);
            final HttpHost defaultProxy = ConnRouteParams.getDefaultProxy(params);
            final boolean secure = forcedRouteHost.getSchemeName().equalsIgnoreCase("https");

            HttpRoute route;
            if (defaultProxy == null)
            {
                route = new HttpRoute(forcedRouteHost, local, secure);
            }
            else
            {
                route = new HttpRoute(forcedRouteHost, local, defaultProxy, secure);
            }
            params.setParameter(ConnRoutePNames.FORCED_ROUTE, route);
        }
    }
}