# Keycloak Adapter Configuration Reference

Both the Repository and Share sub-modules of this addon use the Keycloak-provided adapter library to easily integrate with the Keycloak authentication server. In order to retain much of the adapter libraries flexibility when it comes to different deployment scenarios / configurations that Keycloak is able to handle, most of the configuration properties of this library have been exposed for configuration in both the Repository-tier Keycloak authentication subsystem and the Share-tier `share-config-custom.xml`.

Configuration of adapter properties in the Repository-tier subsystem is straight-forward. Properties can be either configured in `alfresco-global.properties` or within the subsystems extension path, e.g. in a `alfresco/extension/subsystems/Authentication/keycloak/keycloak1/*.properties` (assuming the `authentication.chain` contains a value for `keycloak1:keycloak`). All adapter-specific properties use the common key prefix of `keycloak.adapter.`, with the remaining key denoting the specific property to set. In case a particular property of the Keycloak adapter library denotes a map, entries can be specified by simply appending the entry key to property key, e.g. if `keycloak.adapter.propertyX` denotes a map, `keycloak.adapter.propertyX.key1=value1` would set `value1` in the map for the key `key1`.

Configuration of adapter properties in the Share-tier `share-config-custom.xml` is also straight-forward. Instead of using a common property key prefix, the configuration properties are all child elements of the same XML structure. Multiple configuration sections can be defined and their configuration will be properly merged with a reliable last-wins behaviour. Map entries are handled by specifying entry keys as sub-elements of the map-based property. As part of the merging behaviour, any element which is redefined in a later configuration section with an empty value is effectively removed from the configuration - this is in contrast to Alfresco Share's default merging behaviour which generally does not support easy removal of configurations.

`share-config-custom.xml` example for adapter configuration:

```xml
    <config evaluator="string-compare" condition="Keycloak">
        <keycloak-adapter-config>
            <forced-route-url></forced-route-url>
            <auth-server-url>http://localhost:8180/auth</auth-server-url>
            <realm>alfresco</realm>
            <resource>alfresco-share</resource>
            <credentials>   <!-- map-based property -->
                <provider>secret</provider>
                <secret>...</secret>
            </credentials>
        </keycloak-adapter-config>
    </config>
```

## Supported Adapter Properties

Note: This listing does not include the common property key prefix `keycloak.adapter.` that needs to be prepended in Repository-tier configuration.

| Property | Default Value | Description |
| --- | ---: | --- |
| `auth-server-url` | `http://localhost:8180/auth` | Publically resolvable base URL to the Keycloak server to be used in redirect URLs and remote calls |
| `forced-route-url` |  | Alternative base URL for the Keycloak server (excluding path) to be used for calls from Alfresco to Keycloak - useful e.g. in scenarios where the regular `auth-server-url` can not be resolved or round-trips via a public gateway / proxy should be avoided |
| `proxy-url` |  | URL for proxy server to use for calls from Alfresco to Keycloak |
| `realm` | `alfresco` | Technical name of the Keycloak realm |
| `realm-public-key` |  | Fixed public key of the realm (PEM string) - if not set, the public key(s) will be dynamically loaded and automatically refreshed after a configurable amount of times between JSON Web Key Store requests |
| `resource` | `alfresco` / `alfresco-share` | Technical name of the client set up in the realm |
| `ssl-required` | `none` | SSL requirement mode, controlling both redirect URL generation and redirect validation - defaults to `none` for simple default deployment, but should typically be set to `external` (localhost / loopback requests may use HTTP) or `all` |
| `confidential-port` | `-1` | SSL port to use when generating redirect URLs back to an SSL protected Alfresco resource - when a value of `-1` is configured, the addon will try to determine the port from the request, e.g. if a request contains a `X-Forwarded-Port` port with either port `80`/`443`, it is assumed Alfresco is operated behind a proxy and port `443` is used, otherwise the module will try to determine the SSL port from the raw request and fall back to the Tomcat default SSL port `8443`. This property **must to be changed** if Alfresco is operated in any constellation other than previously described. |
| `bearer-only` | `false` | Flag determining whether authentication handling is terminated after checking for bearer token |
| `autodetect-bearer-only` | `false` | Flag determining whether the Keycloak adapter library should attempt to determine if authentication handling for a request should be terminated after checking for bearer token (i.e. XMLHttpRequest, SOAPAction, or partial Faces requests, or any other request that does not accept `text/html`, `text/*` or `*/*` response content types) |
| `enable-basic-auth` | `false` | Flag determining whether the Keycloak adapter library should handle basic authentications - if enabled, this supersedes any Alfresco provided basic authentication handling, limiting users to Keycloak-authenticated users only |
| `public-client` | `false` | Flag whether the client uses the authentication flow of an OAuth public client |
| `credentials` |  | Map of credential parameters use to configure the way the client authenticates against Keycloak for direct requests |
| `credentials.provider` | `secret` | Type of credential provider to use for client authentication - out-of-the-box, this addon supports `secret`, `jwt` and `secret-jwt` providers, while additional providers can be provided via Java's `ServiceLoader` facility, using the `ClientCredentialsProvider` interface in the shaded Repository / Share dependencies sub-module |
| `credentials.secret` |  | Value of the shared secret to use when either the `secret` or `secret-jwt` credential provider is used |
| `credentials.algorithm` | `HS256`  | Signing algorithm to use when the `secret-jwt` credential provider is used |
| `credentials.client-keystore-file` |  | File or class path location of the client's keystore, when the `jwt` credential provider is used |
| `credentials.client-keystore-type` |  | Type of the client's keystore, when the `jwt` credential provider is used |
| `credentials.client-keystore-password` |  | Password of the client's keystore, when the `jwt` credential provider is used |
| `credentials.client-key-password` |  | Password of the client's key inside the keystore, when the `jwt` credential provider is used |
| `credentials.client-key-alias` |  | Alias of the client's key inside the keystore, when the `jwt` credential provider is used |
| `redirect-rewrite-rules` |  | Map of key-value replacement tokens for dynamically rewriting the path of the generated redirect URI - note: only one / the first map entry will actually be processed by the Keycloak adapter library |
| `allow-any-hostname` | `false` | Flag whether to disable the host name verification on the Apache HTTP client used to call Keycloak |
| `disable-trust-manager` | `false` | Flag whether to disable the trust manager on the Apache HTTP client used to call Keycloak |
| `truststore` |  | File or class path location of the client's custom truststore for validating Keycloak's SSL server certificate |
| `truststore-password` |  | Password of the client's custom truststore for validating Keycloak's SSL server certificate |
| `client-keystore` |  | File or class path location of the client's keystore containing its SSL client certificate to be presented to the Keycloak server |
| `client-keystore-password` |  | Password for the client's keystore containing its SSL client certificate to be presented to the Keycloak server |
| `client-key-password` |  | Password for the client's key within the keystore containing its SSL client certificate to be presented to the Keycloak server |
| `connection-pool-size` | `20` | Number of connections in the Apache HTTP clients connection pool for calls to the Keycloak server |
| `always-refresh-token` | `true` | Flag determining whether a user's access token should always be refreshed when its remaining time-to-live is less than the allowed minimum value, or it has already expired - if `false`, user logins in Alfresco will effectively expire and require a new (transparent) authentication via Keycloak, as no component in the addon performs an explicit refresh |
| `adapter-state-cookie-path` |  | The path to use for the client cookie holding adapter state during execution of the authentication redirects - if not set, this will use the context path from the raw request, which is typically the correct value to use |
| `principal-attribute` |  | The name of the attribute to extract from the access token as an override to the token's subject for the name of the authenticated principal - since this addon does not use the principal name for anything (only the `preferred_username`), this configuration likely has no practical effect if changed |
| `token-minimum-time-to-live` |  | The minimum allowed time-to-live for an access token in seconds - if an access token is returned by Keycloak in exchange for an authorisation code or as part of a token refresh with a lower time-to-live, the validation of that token will fail |
| `min-time-between-jwks-requests` | `10` | The minimum time in seconds that must be elapsed between two JSON Web Key Store requests to Keycloak to load public key(s) of the realm |
| `public-key-cache-ttl` | `86400` | Time-to-live in seconds for public key cache entries |
| `ignore-oauth-query-parameter` | `false` | Flag determining whether OAuth `access_token` in an URL query is to be ignored |
| `verify-token-audience` | `true` / `false` | Flag enabling validation of the audience specified in an access token, enabled by default on the Repository-tier - must be disabled if Share or any other application which authenticates users via Keycloak is not delegating user authentication using RFC 8693 OAuth 2.0 Token Exchange |
| `socket-timeout-millis` | `5000` | General socket timeout for the Apache HTTP client used in calls to Keycloak |
| `connection-timeout-millis` | `5000` | Connect timeout for the Apache HTTP client used in calls to Keycloak |
| `connection-ttl-millis` | `-1` | The time-to-live of connections for the Apache HTTP client used in calls to Keycloak |

## Unsupported Adapter Properties

This listing details configuration properties from the Keycloak adapter library which are not supported by this addon and may result in `UnsupportedOperationException` or other errors potentially being triggered at runtime when set to a non-default value.

| Property | Default Value | Description |
| --- | ---: | --- |
| `use-resource-role-mappings` | `false` | Flag effectively limited to determining whether resource config on Keycloak can override the realm's caller verification setting. If caller verification is required, clients must provide a certificate. - This is not supported by the Keycloak adapter library outside of a JBoss deployment. |
| `enable-cors` | `false` | Flag enabling special handling for CORS requests (e.g. containing an Origin header). - No tests or special considerations have been done for CORS requests, as CORS should not be relevant in a proper Alfresco setup (e.g. whenever CORS would be needed for an ADF app or similar SPA, a simple proxy should do the trick without all the complexities of CORS). Additionally, CORS handling in Alfresco is already [provided out-of-the-box](https://docs.alfresco.com/6.2/concepts/enabling-cors.html). |
| `cors-max-age` | `-1` | Value for the HTTP `Access-Control-Max-Age` response header |
| `cors-allowed-headers` |  | Value for the HTTP `Access-Control-Allow-Headers` response header |
| `cors-allowed-methods` |  | Value for the HTTP `Access-Control-Allow-Methods` response header |
| `cors-exposed-headers` |  | Value for the HTTP `Access-Control-Expose-Headers`response header |
| `expose-token` | `false` | Flag determining whether CORS requests can retrieve a bearer token via special request URI |
| `register-node-at-startup`  | `false` | Flag determining whether the Keycloak adapter will register the node (server) with the Keycloak server - not relevant on Alfresco installations as this relates to [clustering on JBoss server technology](https://www.keycloak.org/docs/latest/securing_apps/#_applicationclustering), this addon already handles relevant caches for potential clustering in Alfresco Enterprise, and the necessary component of the Keycloak adapter library is not used in the integration of this addon |
| `register-node-period` | `-1` | Time in seconds between node registration requests |
| `token-store` | `session` | Mode for how the Keycloak adapter stores user account information - related to clustering like previous two settings and not relevant for the integration as provided by the addon |
| `turn-off-change-session-id-on-login` |  | Completely unused flag in the Keycloak adapter library |
| `policy-enforcer` |  | Complex configuration object determining fine-grained access policies to the Repository / Share application. - This is currently not supported for configuration by the addon due to use of complex object structures |
| `enable-pkce` | `false` | RFC 7636 - Flag enabling the use of the Proof Key for Code Exchange for OAuth public clients. - This has not yet been implemented by the Keycloak adapter library. |