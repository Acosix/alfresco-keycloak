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
package de.acosix.alfresco.keycloak.repo.spring;

import org.alfresco.httpclient.HttpClientFactory.NonBlockingHttpParamsFactory;
import org.alfresco.util.PropertyCheck;
import org.apache.commons.httpclient.params.DefaultHttpParams;
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

    static
    {
        // use same Alfresco NonBlockingHttpParamsFactory as SolrQueryHTTPClient (indirectly) does
        DefaultHttpParams.setHttpParamsFactory(new NonBlockingHttpParamsFactory());
    }

    protected AdapterConfig adapterConfig;

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
    public void setAdapterConfig(final AdapterConfig adapterConfig)
    {
        this.adapterConfig = adapterConfig;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public KeycloakDeployment getObject() throws Exception
    {
        return KeycloakDeploymentBuilder.build(this.adapterConfig);
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