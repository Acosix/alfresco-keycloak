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

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonPropertyOrder;

import org.keycloak.representations.adapters.config.AdapterConfig;

/**
 * Minorly extended configuration for Java based adapters
 *
 * @author Axel Faust
 */
@JsonPropertyOrder({ "realm", "realm-public-key", "auth-server-url", "ssl-required", "resource", "public-client", "credentials",
        "use-resource-role-mappings", "enable-cors", "cors-max-age", "cors-allowed-methods", "cors-exposed-headers", "expose-token",
        "bearer-only", "autodetect-bearer-only", "connection-pool-size", "socket-timeout-millis", "connection-ttl-millis",
        "connection-timeout-millis", "allow-any-hostname", "disable-trust-manager", "truststore", "truststore-password", "client-keystore",
        "client-keystore-password", "client-key-password", "always-refresh-token", "register-node-at-startup", "register-node-period",
        "token-store", "adapter-state-cookie-path", "principal-attribute", "proxy-url", "forced-route-url",
        "turn-off-change-session-id-on-login", "token-minimum-time-to-live", "min-time-between-jwks-requests", "public-key-cache-ttl",
        "policy-enforcer", "ignore-oauth-query-parameter", "verify-token-audience" })
public class ExtendedAdapterConfig extends AdapterConfig
{

    @JsonProperty("forced-route-url")
    protected String forcedRouteUrl;

    /**
     * @return the forcedRouteUrl
     */
    public String getForcedRouteUrl()
    {
        return this.forcedRouteUrl;
    }

    /**
     * @param forcedRouteUrl
     *     the forcedRouteUrl to set
     */
    public void setForcedRouteUrl(final String forcedRouteUrl)
    {
        this.forcedRouteUrl = forcedRouteUrl;
    }

}
