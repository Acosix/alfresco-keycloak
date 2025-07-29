# Getting Started (Simple Configuration)

This section provides the most basic configuration required to use this addon in combination with a Keycloak server (Keycloak version 15.0.2 used as a reference).

## Keycloak

This section will only cover the Keycloak configuration specific to use of this addon. It is recommended that the Keycloak documentation and any available best practices in the wider community are checked in order to create a fully production-ready Keycloak deployment, including e.g. database integration, SSL termination, reverse proxying...

### Enable Token Exchange Feature

This configuration change must be performed if you want Share to use the RFC 8693 OAuth 2.0 Token Exchange functionality to delegate the user authentication to the Repository backend. This feature is not enabled in Keycloak by default. If this feature is not enabled in Keycloak, the configuration of Share needs to be adapted to also disable its RFC 8693 OAuth 2.0 Token Exchange support.

In order to enable the feature in Keycloak, the `profile.properties` file needs to be created / modified in the server's configuration folder structure. In the default Keycloak Docker image, the path to this file should be `/opt/jboss/keycloak/standalone/configuration/profile.properties`. The file must contain an entry in the form of `feature.token_exchange=enabled` to enable the RFC 8693 functionality.

### Realm / Client Configuration

Keycloak provides the ability to [import a realm and client configuration from JSON configuration files](https://www.keycloak.org/docs/latest/server_admin/#_export_import), though most non-specialist users / administrators will likely configure the realm and any clients via the Keycloak administration UI. Since there are countless configuration options that can be defined / changed on every level, this section will not provide a literal configuration example, but rather highlight which configuration properties are most relevant for the use of this addon. Note that UI labels may change between Keycloak versions.

Two clients must be created for the Alfresco Repository and Share. The following configuration values should be set:

- "Access Type" `confidential`
- "Standard Flow Enabled" `On`
- "Direct Access Grants Enabled" `On` (if simple user + password login without SSO should be supported)
- "Service Accounts Enabled" `On` (on the client for Alfresco Repository, if active user / group synchronisation *or* the service/web script to expose roles for use e.g. in permission mangement should be supported)
- "Root URL" to the base URL for each application, e.g. `https://acme.com/alfresco`
- "Valid Redirect URLs" `/*`
- "Base URL" `/`
- "Admin URL" to the base URL for each application with the following added sub-path (if Keycloak back-channel requests should be supported)
    - `/wcs/keycloak` on the client for Alfresco Repository
    - `/page/keycloak` on the client Alfresco Share
- "Web Origins" `/`
- "Credentials" => "Client Authenticator" `Client Id and Secret` (validation based on shared secret)
    - the generated secret for each client needs to be stored for use in Alfresco configuration files
- "Client Scopes" => "Setup" => "Default Client Scopes"
    - `email` and `profile` (on the client for Alfresco Repository, if mapping of person from access / identity tokens should be supported)
    - `roles` (on the client for Alfresco Repository, if mapping of authorities from Keycloak roles should be supported)
- "Mappers" => "Add Builtin" `groups` (on the client for Alfresco Repository, if mapping of authorities from Keycloak groups should be supported)
- "Service Account Roles" (on the client for Alfresco Repository, if active user / group synchronisation *or* the service/web script to expose roles for use e.g. in permission mangement should be supported)
    - Assign client roles `query-groups`, `query-users`, `view-users` and `view-clients` on the client `realm-management`
- When using Keycloak 23 or newer, you must turn on "Exclude Issuer From Authentication Response" under "Advanced" => "OpenID Connect Compatibility Modes" for both clients
    
If the RFC 8693 OAuth 2.0 Token Exchange functionality is to be used for delegation of user authentication from Share to the Repository, an authorisation policy needs to be defined on the pre-existing client `realm-management`. The necessary elements can all be configured in the "Authorization" tab in the configuration of that client. The following elements must be created (if not pre-existing) and/or associated with one another.

- "Authorization Scopes" `token-exchange`
- "Resources" `client.resource.<idOfRepositoryClient>`
    - "Type" `Client`
    - "Scopes" `view`, `map-roles-client-scope`, `configure`, `map-roles`, `manage`, `token-exchange`, `map-roles-composite` (`token-exchange` is required for the feature, the others are typically created by default when an optional Keycloak feature for simplified authorisation management is used - if these do not exist, they can be manually created in "Authorization Scopes")
- "Permissions"
    - `view.permission.client.<idOfRepositoryClient>`
    - `map-roles-client-scope.permission.client.<idOfRepositoryClient>`
    - `configure.permission.client.<idOfRepositoryClient>`
    - `map-roles.permission.client.<idOfRepositoryClient>`
    - `manage.permission.client.<idOfRepositoryClient>`
    - `token-exchange.permission.client.<idOfRepositoryClient>`
    - `map-roles-composite.permission.client.<idOfRepositoryClient>`
- "Policies" `<idOfRepositoryClient>-token-exchange`
    - "Logic" `Positive`
    - "Clients" `<idOfShareClient>`

### Roles / Groups

Unless disabled, the Repository module of this addon can synchronise users / groups, and map groups or roles from the access / identity token as authorities of the user. In the default configuration of the module, all users and groups are synchronised, all roles defined as realm-level roles will be mapped as `ROLE_KEYCLOAK_<realm>_<role>`, and all client roles of the Alfresco Repository client are mapped as `ROLE_KEYCLOAK_<realm>_<idOfRepositoryClient>_<role>`. The following special cases are handled by default with regards to Alfresco Repository client roles (all of these roles do not exist by default and must be created if they are to be used):

- `admin` mapped as `ROLE_ADMINISTRATOR`
- `guest` mapped as `ROLE_GUEST`
- `model-admin` mapped as `GROUP_MODEL_ADMINISTRATORS`
- `search-admin` mapped as `GROUP_SEARCH_ADMINISTRATORS`
- `site-admin` mapped as `GROUP_SITE_ADMINISTRATORS`

Additionally, these client roles need to be assigned to a user or group, directly or indirectly via another (realm) role, in order to take effect when authenticating to Alfresco via Keycloak.

The scope of users / gropus to be synchronised can be restricted in the default configuration via optional group containment conditions. In order to use these, one or more groups needs to be created in the realm configuration which will either directly or indirectly contain all the users / groups to be synchronised. The paths or IDs of these groups needs to be stored for use in Alfresco configuration.

## Alfresco Repository

The Keycloak authentication subsystem is enabled by putting a single instance of it in the authentication chain property, e.g. by specifying

```
authentication.chain=alfrescoNtlm1:alfrescoNtlm,keycloak1:keycloak
```

in the `alfresco-global.properties` file, or via other supported means of configuration (e.g. -D flags in `JAVA_OPTS` in Docker-based deployments). Since it rarely (if ever) makes sense to have more than one instance of the Keycloak authentication subsystem in the chain, all configuration properties specific for this type of subsystem can also be set in the `alfresco-global.properties` file, though it is generally recommended (Acosix recommendation, not necessarily documented as such by Alfresco) to use the proper subsystem configuration paths. For the above authentication chain, custom configuration properties files can be placed in the configuration path `alfresco/extension/subsystems/Authentication/keycloak/keycloak1/*.properties`.

The following core configuration properties can be set (more extensive list in the [reference](./Reference-Repository-Subsystem.md)), with only the `keycloak.adapter.auth-server-url`, `...realm`, `...resource`, and `...credentials.secret` being absolutely required for a minimal configuration (Note: whenever `...` is used as a prefix, it refers to the prefix of the previous full-length property):

| Property | Default Value | Description |
| --- | ---: | --- |
| `keycloak.authentication.enabled` | `true` | Flag enabling authentication support via this subsystem instance |
| `...sso.enabled` | `true` | Flag enabling single sign-on (SSO) authentication support via this subsystem instance |
| `...handlePublicApi` | `false` | Flag enabling inclusion of the Public ReST API in SSO handling - disabled by default as all other means of SSO handling in Alfresco typically do not (fully) cover the Public ReST API |
| `...allowTicketLogons` | `true` | Flag enabling support of Alfresco authentication tickets in the SSO handling logic |
| `...allowHttpBasicLogon` | `true` | Flag enabling support of HTTP Basic authentication in the SSO handling logic, mapping to the simple user + password authentication via this subsystems `AuthenticationComponent` |
| `...allowUserNamePasswordLogin` | `true` | Flag enabling support of user + password authentication via this subsystems `AuthenticationComponent` |
| `...mapAuthorities` | `true` | Flag enabling mapping of authorities from access / identity tokens (supported for both SSO and user + password authentication) |
| `...mapPersonPropertiesOnLogin` | `true` | Flag enabling mapping of person attributes from access / identity tokens (supported for both SSO and user + password authentication) |
| `keycloak.synchronization.enabled` | `true` | Flag enabling synchronisation support via this subsystem instance |
| `...userFilter.containedInGroup.property.groupPaths` |  | Comma-separated list of group paths (e.g. `/Group A/Group B,/Group A/Group C`) to use in filtering which users are synchronised to Alfresco (by default - configured separately - any match qualifies, and transitive containment is considered) |
| `...userFilter.containedInGroup.property.groupIds` |  | Comma-separated list of group IDs to use in filtering which users are synchronised to Alfresco (by default - configured separately - any match qualifies, and transitive containment is considered) |
| `...groupFilter.containedInGroup.property.groupPaths` |  | Comma-separated list of group paths (e.g. `/Group A/Group B,/Group A/Group C`) to use in filtering which groups are synchronised to Alfresco (by default - configured separately - any match qualifies, and transitive containment is considered) |
| `...groupFilter.containedInGroup.property.groupIds` |  | Comma-separated list of group IDs to use in filtering which groups are synchronised to Alfresco (by default - configured separately - any match qualifies, and transitive containment is considered) |
| `keycloak.adapter.auth-server-url` | `http://localhost:8180/auth` | Publically resolvable base URL to the Keycloak server to be used in redirect URLs and remote calls |
| `...forced-route-url` |  | Alternative base URL for the Keycloak server (excluding path) to be used for calls from Alfresco to Keycloak - useful e.g. in scenarios where the regular `auth-server-url` can not be resolved by the Alfresco Repository host or round-trips via a public gateway / proxy should be avoided |
| `...realm` | `alfresco` | Technical name of the Keycloak realm |
| `...resource` | `alfresco` | Technical name of the client set up for the Alfresco Repository in the realm |
| `...credentials.secret` |  | Shared secret for validation of authorisation codes / access tokens |
| `...verify-token-audience` | `true` | Flag enabling validation of the audience specified in an access token - must be disabled if Share or any other application which authenticates users via Keycloak is not delegating user authentication using RFC 8693 OAuth 2.0 Token Exchange |

## Alfresco Share

By installing the addon on the Repository tier and allowing user + password logins to be supported, Alfresco Share will automatically and transparently authenticate users against Keycloak when a login occurs via the default login form. Installing the addon on the Share tier enables extended support for single sign-on (SSO) authentication directly on the Share tier. When installed, support for Keycloak SSO authentication is pre-enabled by the default configuration bundled with the addon, and only requires the enablement of `external-auth` on the `alfresco` remote connector to be effectively activated. Adding an additional `Keycloak` configuration section in the `share-config-custom.xml` file allows to complement / modify the default configuration. The section is split into two primary sub-elements - the `keycloak-auth-config`, which handles configuration specific to features implemented as part of this addon, and `keycloak-adapter-config`, which handles configuration relating to the Keycloak adapter library used to integrate with the Keycloak server. The latter section uses identical configuration properties as the Repository subsystem (all properties with the `keycloak.adapter.` key prefix).
The following showcases an example configuration block:

```xml
    <config evaluator="string-compare" condition="Keycloak">
        <keycloak-auth-config>
            <enhance-login-form>true</enhance-login-form>
            <enable-sso-filter>true</enable-sso-filter>
            <force-keycloak-sso>false</force-keycloak-sso>
            <perform-token-exchange>true</perform-token-exchange>
        </keycloak-auth-config>
        <keycloak-adapter-config>
            <forced-route-url></forced-route-url>
            <auth-server-url>http://localhost:8180/auth</auth-server-url>
            <realm>alfresco</realm>
            <resource>alfresco-share</resource>
            <credentials>
                <provider>secret</provider>
                <secret>...</secret>
            </credentials>
        </keycloak-adapter-config>
    </config>
```

| `keycloak-auth-config` key | Default Value | Description |
| --- | ---: | --- |
| `enhance-login-form` | `true` | Flag enabling the inclusion of an additional "Log in via SSO" button in the Share login form |
| `enable-sso-filter` | `true` | Flag enabling single sign-on (SSO) authentication support |
| `force-keycloak-sso` | `false` | Flag enabling forced SSO, meaning the user is automatically redirected to Keycloak for authentication instead of being shown the Share login form |
| `perform-token-exchange` | `true` | Flag enabling the use of RFC 8693 OAuth 2.0 Token Exchange for delegating user authentication to the Alfresco Repository |

**Note**: When the `enable-sso-filter` is set to `true`, the Keycloak authentication subsystem must be enabled on the Alfresco Repository for correct operation.

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
