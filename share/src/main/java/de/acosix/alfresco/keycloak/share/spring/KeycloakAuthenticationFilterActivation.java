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
package de.acosix.alfresco.keycloak.share.spring;

import org.alfresco.util.PropertyCheck;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.BeansException;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.beans.factory.config.ConfigurableListableBeanFactory;
import org.springframework.beans.factory.config.RuntimeBeanReference;
import org.springframework.beans.factory.support.BeanDefinitionRegistry;
import org.springframework.beans.factory.support.BeanDefinitionRegistryPostProcessor;
import org.springframework.beans.factory.support.GenericBeanDefinition;

import de.acosix.alfresco.keycloak.share.web.KeycloakAuthenticationFilter;

/**
 * @author Axel Faust
 */
public class KeycloakAuthenticationFilterActivation implements BeanDefinitionRegistryPostProcessor, InitializingBean
{

    private static final String DEFAULT_SSO_AUTHENTICATION_FILTER_NAME = "SSOAuthenticationFilter";

    private static final Logger LOGGER = LoggerFactory.getLogger(KeycloakAuthenticationFilterActivation.class);

    protected String moduleId;

    /**
     * {@inheritDoc}
     */
    @Override
    public void afterPropertiesSet()
    {
        PropertyCheck.mandatory(this, "moduleId", this.moduleId);
    }

    /**
     * @param moduleId
     *            the moduleId to set
     */
    public void setModuleId(final String moduleId)
    {
        this.moduleId = moduleId;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void postProcessBeanFactory(final ConfigurableListableBeanFactory beanFactory) throws BeansException
    {
        // NO-OP
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void postProcessBeanDefinitionRegistry(final BeanDefinitionRegistry registry) throws BeansException
    {
        final String keycloakFilterBeanName = this.moduleId + "." + KeycloakAuthenticationFilter.class.getSimpleName();

        if (registry.containsBeanDefinition(keycloakFilterBeanName))
        {
            LOGGER.debug("Activating KeycloakAuthenticationFilter bean");

            // re-register default filter under different name
            final BeanDefinition defaultSsoAuthenticationFilter = registry.getBeanDefinition(DEFAULT_SSO_AUTHENTICATION_FILTER_NAME);
            registry.removeBeanDefinition(DEFAULT_SSO_AUTHENTICATION_FILTER_NAME);
            final String defaultSsoAuthenticationFilterReplacementName = this.moduleId + ".default"
                    + DEFAULT_SSO_AUTHENTICATION_FILTER_NAME;
            registry.registerBeanDefinition(defaultSsoAuthenticationFilterReplacementName, defaultSsoAuthenticationFilter);

            // re-register our filter under default name
            final BeanDefinition keycloakSsoAuthenticationFilter = registry.getBeanDefinition(keycloakFilterBeanName);
            registry.removeBeanDefinition(keycloakFilterBeanName);
            ((GenericBeanDefinition) keycloakSsoAuthenticationFilter).setAbstract(false);
            keycloakSsoAuthenticationFilter.getPropertyValues().add("defaultSsoFilter",
                    new RuntimeBeanReference(defaultSsoAuthenticationFilterReplacementName));
            registry.registerBeanDefinition(DEFAULT_SSO_AUTHENTICATION_FILTER_NAME, keycloakSsoAuthenticationFilter);

            LOGGER.debug("Activated KeycloakAuthenticationFilter bean");
        }
        else
        {
            LOGGER.error("Cannot activate KeycloakAuthenticationFilter bean as abstract bean {} was not found in Spring context",
                    keycloakFilterBeanName);
        }
    }
}
