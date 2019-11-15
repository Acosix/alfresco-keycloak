/*
 * Copyright 2019 Acosix GmbH
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

import java.util.concurrent.TimeUnit;

import org.alfresco.util.PropertyCheck;
import org.keycloak.adapters.HttpClientBuilder;
import org.keycloak.adapters.KeycloakDeployment;
import org.keycloak.adapters.KeycloakDeploymentBuilder;
import org.keycloak.representations.adapters.config.AdapterConfig;
import org.springframework.beans.factory.FactoryBean;
import org.springframework.beans.factory.InitializingBean;

/**
 * @author Axel Faust
 */
public class KeycloakDeploymentBeanFactory implements FactoryBean<KeycloakDeployment>, InitializingBean
{

    protected AdapterConfig adapterConfig;

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
        keycloakDeployment.setClient(httpClientBuilder.build(this.adapterConfig));

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
}