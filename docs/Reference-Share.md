# Share Reference

## Keycloak Configuration

By installing the addon on the Repository tier and allowing user + password logins to be supported, Alfresco Share will automatically and transparently authenticate users against Keycloak when a login occurs via the default login form. Installing the addon on the Share tier enables extended support for single sign-on (SSO) authentication directly on the Share tier. When installed, support for Keycloak SSO authentication is pre-enabled by the default configuration bundled with the addon, and only requires the enablement of `external-auth` on the `alfresco` remote connector to be effectively activated. Adding an additional `Keycloak` configuration section in the `share-config-custom.xml` file allows to complement / modify the default configuration. The section is split into two primary sub-elements - the `keycloak-auth-config`, which handles configuration specific to features implemented as part of this addon, and `keycloak-adapter-config`, which handles configuration relating to the Keycloak adapter library used to integrate with the Keycloak server. The general structure of the Keycloak configuration section is demonstrated with the following XML snippet:

```xml
    <config evaluator="string-compare" condition="Keycloak">
        <keycloak-auth-config>
            <!-- options -->
        </keycloak-auth-config>
        <keycloak-adapter-config>
            <!-- options -->
        </keycloak-adapter-config>
    </config>
```

The configuration options for the `keycloak-adapter-config` sub-element are [documented separately](./Reference-Adapter.md) as they are nearly identical / consistent across both Repository and Share layers of the addon. The following lists the configuration elements that are supported for the `keycloak-auth-config`. All options are simply specified as elements with plain text context.

| Property | Default Value | Description |
| --- | ---: | --- |
| `enable-sso-filter` | `true` | Flag determining whether the SSO authentication handling logic is enabled - only if this is enabled (and `external-auth` configured for the main `alfresco` remote connector) will any of the functionality of the Share addon work. |
| `enhance-login-form` | `true` | Flag determining whether an additional "Log in via SSO" button is to be included in the Share login form |
| `force-keycloak-sso` | `false` | Flag determining whether SSO authentication should be forced, meaning users are automatically redirected for authentication to Keycloak and the login form is only accessible by using a direct URL access bypass |
| `body-buffer-limit` | `10485760` | Size limit for request bodies that can be cached / stored if a request needs to be redirected to Keycloak for SSO authentication - requests larger than this limit will fail and require that the client first authenticate in a simple request, and use either authentication tickets or HTTP session cookies to perform the payload request re-using the established authentication |
| `session-mapper-limit` | `10000` | Size limit (in number of sessions) of the in-memory mapper of HTTP and SSO session IDs in order to allow back-channel logout requests to be properly handled. As HTTP sessions are not replicated in default Alfresco Share, the session mapper only handles local sessions for an individual Share node. |
| `ignore-default-filter` | `true` | Flag determining whether the default SSO filter should be ignored / skipped when `enable-sso-filter` is enabled, in order to avoid functionality conflicts, e.g. via redundant handling of `Authorization` HTTP headers. |
| `perform-token-exchange` | `true` | Flag determining whether RFC 8693 OAuth 2.0 Token Exchange is to be performed to delegate user authentication to the Repository-tier. |
| `alfresco-resource-name` | `alfresco` | Technical name of the client configured for the Repository-tier - this value is used to perform the RFC 8693 OAuth 2.0 Token Exchange and **must** be identical to the corresponding value configured in the Repository subsystem for Keycloak.. |

## Remote Configuration

Similar to Alfresco's out-of-the-box SSO mechanisms for Share, the use of Keycloak for SSO requires that the Remote endpoint configuration be changed to use the `/alfresco/wcs` endpoint instead of the default `/alfresco/s` endpoint. Additionally, a special connector must be used to properly use the access token to authenticate against the Alfresco Repository, and the `external-auth` flag set to `true`. This can all be done by adding a section like the following:

```xml
    <config evaluator="string-compare" condition="Remote">
        <remote>
            <connector>
                <id>alfrescoCookie</id>
                <name>Alfresco Connector</name>
                <description>Connects to an Alfresco instance using cookie-based authentication and awareness of Keycloak access tokens</description>
                <class>de.acosix.alfresco.keycloak.share.remote.AccessTokenAwareSlingshotAlfrescoConnector</class>
            </connector>

            <endpoint>
                <id>alfresco</id>
                <name>Alfresco - user access</name>
                <description>Access to Alfresco Repository WebScripts that require user authentication</description>
                <connector-id>alfrescoCookie</connector-id>
                <endpoint-url>http://localhost:8080/alfresco/wcs</endpoint-url>
                <identity>user</identity>
                <external-auth>true</external-auth>
            </endpoint>

            <endpoint>
                <id>alfresco-feed</id>
                <name>Alfresco Feed</name>
                <description>Alfresco Feed - supports basic HTTP authentication via the EndPointProxyServlet</description>
                <connector-id>alfrescoCookie</connector-id>
                <endpoint-url>http://localhost:8080/alfresco/wcs</endpoint-url>
                <basic-auth>true</basic-auth>
                <identity>user</identity>
                <external-auth>true</external-auth>
            </endpoint>

            <endpoint>
                <id>alfresco-api</id>
                <parent-id>alfresco</parent-id>
                <name>Alfresco Public API - user access</name>
                <description>Access to Alfresco Repository Public API that require user authentication. This makes use of the authentication
                    that is provided by parent 'alfresco' endpoint.
                </description>
                <connector-id>alfrescoCookie</connector-id>
                <endpoint-url>http://localhost:8080/alfresco/api</endpoint-url>
                <identity>user</identity>
                <external-auth>true</external-auth>
            </endpoint>
        </remote>
    </config>
```