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

import java.util.Arrays;
import java.util.Map;

import org.junit.Assert;
import org.junit.Test;
import org.keycloak.representations.adapters.config.AdapterConfig;
import org.springframework.extensions.config.Config;
import org.springframework.extensions.config.ConfigElement;
import org.springframework.extensions.config.ConfigSource;
import org.springframework.extensions.config.source.UrlConfigSource;
import org.springframework.extensions.config.xml.XMLConfigService;

/**
 * @author Axel Faust
 */
public class KeycloakAdapterConfigTest
{

    @Test
    public void loadDefaultConfig()
    {
        // default-config.xml copied from src/main/config into src/test/resoruces because default resource filtering will not copy into
        // build / class path
        final ConfigSource configSource = new UrlConfigSource(Arrays.asList("classpath:default-config.xml"), true);
        final XMLConfigService configService = new XMLConfigService(configSource);
        configService.initConfig();

        final Config keycloakConfigSection = configService.getConfig(KeycloakConfigConstants.KEYCLOAK_CONFIG_SECTION_NAME);

        final ConfigElement keycloakAuthConfigEl = keycloakConfigSection.getConfigElement(KeycloakAuthenticationConfigElement.NAME);
        Assert.assertTrue(keycloakAuthConfigEl instanceof KeycloakAuthenticationConfigElement);
        final KeycloakAuthenticationConfigElement keycloakAuthConfig = (KeycloakAuthenticationConfigElement) keycloakAuthConfigEl;

        Assert.assertTrue(keycloakAuthConfig.getEnhanceLoginForm());
        Assert.assertTrue(keycloakAuthConfig.getEnableSsoFilter());
        Assert.assertFalse(keycloakAuthConfig.getForceKeycloakSso());
        Assert.assertEquals(Integer.valueOf(10485760), keycloakAuthConfig.getBodyBufferLimit());
        Assert.assertEquals(Integer.valueOf(1000), keycloakAuthConfig.getSessionMapperLimit());

        final KeycloakAdapterConfigElement keycloakAdapterConfig = (KeycloakAdapterConfigElement) keycloakConfigSection
                .getConfigElement(KeycloakAdapterConfigElement.NAME);

        Assert.assertEquals("http://localhost:8180/auth", keycloakAdapterConfig.getFieldValue("auth-server-url"));
        Assert.assertEquals("alfresco", keycloakAdapterConfig.getFieldValue("realm"));
        Assert.assertEquals("alfresco", keycloakAdapterConfig.getFieldValue("resource"));
        Assert.assertEquals("none", keycloakAdapterConfig.getFieldValue("ssl-required"));
        Assert.assertEquals(Boolean.FALSE, keycloakAdapterConfig.getFieldValue("public-client"));

        Assert.assertTrue(keycloakAdapterConfig.getFieldValue("credentials") instanceof Map<?, ?>);
        final Map<?, ?> credentials = (Map<?, ?>) keycloakAdapterConfig.getFieldValue("credentials");
        Assert.assertEquals("secret", credentials.get("provider"));

        final AdapterConfig adapterConfig = keycloakAdapterConfig.buildAdapterConfiguration();
        Assert.assertEquals("http://localhost:8180/auth", adapterConfig.getAuthServerUrl());
        Assert.assertEquals("alfresco", adapterConfig.getRealm());
        Assert.assertEquals("alfresco", adapterConfig.getResource());
        Assert.assertEquals("none", adapterConfig.getSslRequired());
        Assert.assertFalse(adapterConfig.isPublicClient());

        Assert.assertNotNull(adapterConfig.getCredentials());
        Assert.assertEquals("secret", adapterConfig.getCredentials().get("provider"));
    }

    @Test
    public void loadMergedConfig()
    {
        // default-config.xml copied from src/main/config into src/test/resoruces because default resource filtering will not copy into
        // build / class path
        final ConfigSource configSource = new UrlConfigSource(
                Arrays.asList("classpath:default-config.xml", "classpath:addendum-config.xml"), true);
        final XMLConfigService configService = new XMLConfigService(configSource);
        configService.initConfig();

        final Config keycloakConfigSection = configService.getConfig(KeycloakConfigConstants.KEYCLOAK_CONFIG_SECTION_NAME);

        final ConfigElement keycloakAuthConfigEl = keycloakConfigSection.getConfigElement(KeycloakAuthenticationConfigElement.NAME);
        Assert.assertTrue(keycloakAuthConfigEl instanceof KeycloakAuthenticationConfigElement);
        final KeycloakAuthenticationConfigElement keycloakAuthConfig = (KeycloakAuthenticationConfigElement) keycloakAuthConfigEl;

        Assert.assertFalse(keycloakAuthConfig.getEnhanceLoginForm());
        Assert.assertFalse(keycloakAuthConfig.getEnableSsoFilter());
        Assert.assertFalse(keycloakAuthConfig.getForceKeycloakSso());
        Assert.assertEquals(Integer.valueOf(10485760), keycloakAuthConfig.getBodyBufferLimit());
        Assert.assertEquals(Integer.valueOf(2000), keycloakAuthConfig.getSessionMapperLimit());

        final KeycloakAdapterConfigElement keycloakAdapterConfig = (KeycloakAdapterConfigElement) keycloakConfigSection
                .getConfigElement(KeycloakAdapterConfigElement.NAME);

        Assert.assertEquals("http://localhost:8080/auth", keycloakAdapterConfig.getFieldValue("auth-server-url"));
        Assert.assertEquals("my-realm", keycloakAdapterConfig.getFieldValue("realm"));
        Assert.assertEquals("alfresco", keycloakAdapterConfig.getFieldValue("resource"));
        Assert.assertEquals("none", keycloakAdapterConfig.getFieldValue("ssl-required"));
        Assert.assertEquals(Boolean.FALSE, keycloakAdapterConfig.getFieldValue("public-client"));
        Assert.assertEquals(Boolean.TRUE, keycloakAdapterConfig.getFieldValue("always-refresh-token"));
        Assert.assertEquals(Integer.valueOf(123), keycloakAdapterConfig.getFieldValue("connection-pool-size"));

        Assert.assertTrue(keycloakAdapterConfig.getFieldValue("credentials") instanceof Map<?, ?>);
        final Map<?, ?> credentials = (Map<?, ?>) keycloakAdapterConfig.getFieldValue("credentials");
        Assert.assertEquals("differentSecret", credentials.get("provider"));

        final AdapterConfig adapterConfig = keycloakAdapterConfig.buildAdapterConfiguration();
        Assert.assertEquals("http://localhost:8080/auth", adapterConfig.getAuthServerUrl());
        Assert.assertEquals("my-realm", adapterConfig.getRealm());
        Assert.assertEquals("alfresco", adapterConfig.getResource());
        Assert.assertEquals("none", adapterConfig.getSslRequired());
        Assert.assertFalse(adapterConfig.isPublicClient());
        Assert.assertTrue(adapterConfig.isAlwaysRefreshToken());
        Assert.assertEquals(123, adapterConfig.getConnectionPoolSize());

        Assert.assertNotNull(adapterConfig.getCredentials());
        Assert.assertEquals("differentSecret", adapterConfig.getCredentials().get("provider"));
    }
}
