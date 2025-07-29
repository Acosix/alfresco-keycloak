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
package de.acosix.alfresco.keycloak.share.config;

import org.dom4j.Element;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.extensions.config.ConfigElement;
import org.springframework.extensions.config.xml.elementreader.ConfigElementReader;

/**
 * @author Axel Faust
 */
public class KeycloakAuthenticationConfigElementReader implements ConfigElementReader
{

    private static final Logger LOGGER = LoggerFactory.getLogger(KeycloakAuthenticationConfigElementReader.class);

    /**
     * {@inheritDoc}
     */
    @Override
    public ConfigElement parse(final Element element)
    {
        final KeycloakAuthenticationConfigElement configElement = new KeycloakAuthenticationConfigElement();

        final Element enhanceLoginForm = element.element("enhance-login-form");
        if (enhanceLoginForm != null)
        {
            final String value = enhanceLoginForm.getTextTrim();
            configElement.setEnhanceLoginForm(value.isEmpty() ? null : Boolean.valueOf(value));
        }

        final Element enableSsoFilter = element.element("enable-sso-filter");
        if (enableSsoFilter != null)
        {
            final String value = enableSsoFilter.getTextTrim();
            configElement.setEnableSsoFilter(value.isEmpty() ? null : Boolean.valueOf(value));
        }

        final Element forceKeycloakSso = element.element("force-keycloak-sso");
        if (forceKeycloakSso != null)
        {
            final String value = forceKeycloakSso.getTextTrim();
            configElement.setForceKeycloakSso(value.isEmpty() ? null : Boolean.valueOf(value));
        }

        final Element rememberKeycloakSso = element.element("remember-keycloak-sso");
        if (rememberKeycloakSso != null)
        {
            final String value = rememberKeycloakSso.getTextTrim();
            configElement.setRememberKeycloakSso(value.isEmpty() ? null : Boolean.valueOf(value));
        }

        final Element bodyBufferLimit = element.element("body-buffer-limit");
        if (bodyBufferLimit != null)
        {
            final String value = bodyBufferLimit.getTextTrim();
            configElement.setBodyBufferLimit(value.isEmpty() ? null : Integer.valueOf(value));
        }

        final Element sessionMapperLimit = element.element("session-mapper-limit");
        if (sessionMapperLimit != null)
        {
            final String value = sessionMapperLimit.getTextTrim();
            configElement.setSessionMapperLimit(value.isEmpty() ? null : Integer.valueOf(value));
        }

        final Element ignoreDefaultFilter = element.element("ignore-default-filter");
        if (ignoreDefaultFilter != null)
        {
            final String value = ignoreDefaultFilter.getTextTrim();
            configElement.setIgnoreDefaultFilter(value.isEmpty() ? null : Boolean.valueOf(value));
        }

        final Element performTokenExchange = element.element("perform-token-exchange");
        if (performTokenExchange != null)
        {
            final String value = performTokenExchange.getTextTrim();
            configElement.setPerformTokenExchange(value.isEmpty() ? null : Boolean.valueOf(value));
        }

        final Element alfrescoResourceName = element.element("alfresco-resource-name");
        if (alfrescoResourceName != null)
        {
            final String value = alfrescoResourceName.getTextTrim();
            configElement.setAlfrescoResourceName(value.isEmpty() ? null : value);
        }

        LOGGER.debug("Read configuration element {} from XML section", configElement);

        return configElement;
    }

}
