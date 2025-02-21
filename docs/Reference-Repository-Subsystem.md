# Repository Subsystem Reference

The Keycloak authentication subsystem is enabled by putting a single instance of it in the authentication chain property, e.g. by specifying

```
authentication.chain=alfrescoNtlm1:alfrescoNtlm,keycloak1:keycloak
```

in the `alfresco-global.properties` file, or via other supported means of configuration (e.g. -D flags in `JAVA_OPTS` in Docker-based deployments).

Since it rarely (if ever) makes sense to have more than one instance of the Keycloak authentication subsystem in the chain, all configuration properties specific for this type of subsystem can be set in the `alfresco-global.properties` file, though it is generally recommended (Acosix recommendation, not necessarily documented as such by Alfresco) to use the proper subsystem configuration paths. For a subsystem instance listed in the authentication chain as `keycloak1:keycloak`, custom configuration properties files can be placed in the configuration path `alfresco/extension/subsystems/Authentication/keycloak/keycloak1/*.properties`.

The supported configuration properties can be grouped in the following categories:

- [Keycloak adapter configuration](./Reference-Adapter.md)
- Authentication properties
- Synchronisation properties
- Role mapping properties

## Authentication Properties

### High-Level

The following authentication configuration properties are supported by the subsystem. All property keys in the table are listed without the common `keycloak.authentication.` key prefix.

| Property | Default Value | Description |
| --- | ---: | --- |
| `enabled` | `true` | Flag determining whether general authentication functionality is enabled |
| `sso.enabled` | `true` | Flag determining whether SSO authentication functionality is enabled |
| `sso.handlePublicApi` | `false` | Flag determining whether SSO authentication also covers the Public v1 ReST API - disabled by default as all other means of SSO handling in Alfresco typically do not (fully) cover the Public ReST API |
| `sso.originalRequestUrlHeaderName` | `X-Original-Request-URL` | Name of a custom HTTP request header that contains the original request URL - the header may need to be set in scenarios with potentially multiple layers of reverse proxies or any kind of URL rewriting in the proxy layer that should be re-executed when Keycloak redirects clients back to Alfresco after authentication; by default, this header is not set by any of the typical proxy configurations in Alfresco documentation / samples |
| `defaultAdministratorUserNames` |  | Comma-separated names of users that should always be considered administrator if authenticated via the subsystem - supported for consistency with other authentication subsystems, but typically such a property should not be necessary |
| `allowTicketLogons` | `true` | Flag determining whether the SSO authentication also checks and validates Alfresco authentication tickets provided via the `ticket` or `alf_ticket` URL query parameters (presence of `ticket` supersedes `alf_ticket`) |
| `allowHttpBasicLogon` | `true` | Flag determining whether the SSO authentication also processes HTTP Basic authentication requests |
| `allowUserNamePasswordLogin` | `true` | Flag determining whether the authentication supports simple user + password authentications, either via `AuthenticationComponent.authenticate(String, char[])` API or HTTP Basic authentication requests |
| `failExpiredTicketTokens` | `false` | Flag determining whether the validation of Alfresco authentication tickets should fail if the ticket-owning user was at any point during the ticket's lifecycle associated with a Keycloak-based authentication (via a successful user + password login), and the underlying access token has expired and could not be refreshed. Since Alfresco tickets are generally reused for the same user no matter how that user was authenticated, and have their own expiry lifecycle, failing ticket validation can have unintended consequences. If the access token has expired and validation is not set to fail, the only consequence is that Keycloak authorities will no longer be mapped into the user's authorisation context. It is **recommended** to align Alfresco ticket expiry with the validity period of Keycloak refresh tokens. Linking Alfresco tickets with Keycloak tokens is required to support various ticket-based client authentications scenarios in e.g. Share or applications using the Public v1 Rest API, especially relating to role mapping. |
| `allowGuestLogin` | `true` | Flag determining whether the authentication allows authentication as a guest user - currently not actively used / enforced as Keycloak authentication cannot determine whether a user would be a guest before authentication (and implicit role mapping) has already occurred |
| `mapAuthorities` | `true` | Flag determining whether the authorities should be mapped from roles / groups contained in Keycloak access / identity tokens |
| `mapPersonPropertiesOnLogin` | `true` | Flag determining whether person attributes should be mapped from Keycloak access / identity tokens |
| `authenticateFTP` | `true` | Flag determining whether this subsystem supports authentication in Alfresco's FTP functionality in the `fileServers` subsystem |
| `silentRemoteUserValidationFailure` | `true` | Flag determining whether failure to validate `Bearer` tokens in the subsystem's `RemoteUserMapper` should be silent (logged but not escalated) or fail the entire request |
| `bodyBufferLimit` | `10485760` | Size limit for request bodies that can be cached / stored if a request needs to be redirected to Keycloak for SSO authentication - requests larger than this limit will fail and require that the client first authenticate in a simple request, and use either authentication tickets or HTTP session cookies to perform the payload request re-using the established authentication |

### Technical - Person Property Mapping

The following technical authentication configuration properties are supported by the subsystem to control the default mapping of person properties from Keycloak access / identity tokens. All property keys in the table are listed without the common `keycloak.authentication.userToken.default.property.` key prefix.

| Property | Default Value | Description |
| --- | ---: | --- |
| `enabled` | `true` | Flag determining whether the default property mapping is enabled - mapping of properties for person nodes is technically extensible, and in some cases, the default handling may need to be disabled |
| `mapNull` | `true` | Flag determining whether `null` values in specific fields of a token should still be mapped to the corresponding person property - if disabled, mapping of person properties will not remove previously mapped values from Alfresco person nodes if the value has been removed without replacement in Keycloak |
| `mapGivenName` | `true` | Flag determining whether the `givenName` token attribute should be mapped as `cm:firstName` |
| `mapMiddleName` | `true` | Flag determining whether the `middleName` token attribute should be mapped as `cm:middleName` |
| `mapFamilyName` | `true` | Flag determining whether the `familyName` token attribute should be mapped as `cm:lastName` |
| `mapEmail` | `true` | Flag determining whether the `email` token attribute should be mapped as `cm:email` |
| `mapPhoneNumber` | `true` | Flag determining whether the `phoneNumber` token attribute should be mapped |
| `mapPhoneNumberAsMobile` | `false` | Flag determining whether the `phoneNumber` token attribute should be mapped as either `cm:telephone` (`false`) or `cm:mobile` (`true`) |

## Synchronisation Properties

### High-Level

The following synchronisation configuration properties are supported by the subsystem. All property keys in the table are listed without the common `keycloak.synchronization.` key prefix. Note: The configuration properties use the spelling of `synchronization` instead of `synchronisation` as that is the spelling used by Alfresco in the out-of-the-box authentication subsystems.

| Property | Default Value | Description |
| --- | ---: | --- |
| `enabled` | `true` | Flag determining whether general synchronisation functionality is enabled |
| `user` |  | Name of a user account to be used to perform synchronisation-related calls to Keycloak - if not set, the subsystem will use the configured adapter client credentials to use the service account of the client (service account must have been enabled / set up in Keycloak) |
| `password` |  | Password for the user account to be used to perform synchronisation-related calls to Keycloak|
| `requiredClientScopes` |  | Comma-separated list of required client scopes to be requested for the Keycloak token used for authentication on Keycloak API - this may be necessary if an optional client scope has been configured to include/map the required `realm-management` client roles + audience used in Keycloak for access checking |
| `personLoadBatchSize` | `50` | Number of users to retrieve from Keycloak in a single admin API call |
| `groupLoadBatchSize` | `50` | Number of groups to retrieve from Keycloak in a single admin API call |

### Technical - Filtering

The following technical synchronisation configuration properties are supported by the subsystem to control the filtering of users / groups. All properties in the table use the key pattern `keycloak.synchronization.<filterCategory>.<filterType>.property.<property>`.

| Category | Type | Property | Default Value | Description |
| --- | --- | --- | ---: | --- |
| `userFilter` | `containedInGroup` | `groupPaths` |  | Comma-separated list of group paths |
| `userFilter` | `containedInGroup` | `groupIds` |  | Comma-separated list of group IDs |
| `userFilter` | `containedInGroup` | `requireAll` | `false` | Flag determining whether both configured paths and IDs must match or just one |
| `userFilter` | `containedInGroup` | `allowTransitive` | `true` | Flag determining whether transitive or direct containment is checked |
| `userFilter` | `containedInGroup` | `groupLoadBatchSize` |  | Same as high-level `groupLoadBatchSize` in high-level properties (used as default value) - used to load / inspect groups for evaluated user |
| `groupFilter` | `containedInGroup` | `groupPaths` |  | Comma-separated list of group paths |
| `groupFilter` | `containedInGroup` | `groupIds` |  | Comma-separated list of group IDs |
| `groupFilter` | `containedInGroup` | `requireAll` | `false` | Flag determining whether both configured paths and IDs must match or just one |
| `groupFilter` | `containedInGroup` | `allowTransitive` | `true` | Flag determining whether transitive or direct containment is checked |

### Technical - Mapping

The following technical synchronisation configuration properties are supported by the subsystem to control the mapping of user / group attributes. Properties in the table use the key patterns `keycloak.synchronization.<mapperCategory>.<mapperType>.property.<property>` or `keycloak.synchronization.<mapperCategory>.<mapperType>.property.<property>.map.<subKey>`.

| Category | Type | Property | Sub-Key | Default Value | Description |
| --- | --- | --- | --- | ---: | --- |
| `userMapper` | `default` | `enabled` |  | `true` | Flag determining whether the `default` user mapper is enabled |
| `userMapper` | `default` | `mapNull` |  | `true` | Flag determining whether `null` values should still be mapped to the corresponding person property - if disabled, mapping of person properties will not remove previously mapped values from Alfresco person nodes if the value has been removed without replacement in Keycloak |
| `userMapper` | `default` | `mapFirstName` |  | `true` | Flag determining whether the `default` user mapper is enabled |
| `userMapper` | `default` | `mapLastName` |  | `true` | Flag determining whether the `default` user mapper is enabled |
| `userMapper` | `default` | `mapEmail` |  | `true` | Flag determining whether the `default` user mapper is enabled |
| `userMapper` | `default` | `mapEnabledState` |  | `true` | Flag determining whether the `default` user mapper is enabled |
| `userMapper` | `simpleAttributes` | `enabled` |  | `true` | Flag determining whether the `simpleAttribute` user mapper is enabled |
| `userMapper` | `simpleAttributes` | `mapNull` |  | `true` | Flag determining whether `null` values should still be mapped to the corresponding person property - if disabled, mapping of person properties will not remove previously mapped values from Alfresco person nodes if the value has been removed without replacement in Keycloak |
| `userMapper` | `simpleAttributes` | `attributes` | `middleName` | `cm:middleName` | Mapping of Keycloak profile field `middleName` to Alfresco property |
| `userMapper` | `simpleAttributes` | `attributes` | `organization` | `cm:organization` | Mapping of Keycloak profile field `organization` to Alfresco property |
| `userMapper` | `simpleAttributes` | `attributes` | `jobTitle` | `cm:jobtitle` | Mapping of Keycloak profile field `jobTitle` to Alfresco property |
| `userMapper` | `simpleAttributes` | `attributes` | `location` | `cm:location` | Mapping of Keycloak profile field `location` to Alfresco property |
| `userMapper` | `simpleAttributes` | `attributes` | `telephone` | `cm:telephone` | Mapping of Keycloak profile field `telephone` to Alfresco property |
| `userMapper` | `simpleAttributes` | `attributes` | `mobile` | `cm:mobile` | Mapping of Keycloak profile field `mobile` to Alfresco property |
| `userMapper` | `simpleAttributes` | `attributes` | `companyAddress1` | `cm:companyaddress1` | Mapping of Keycloak profile field `companyAddress1` to Alfresco property |
| `userMapper` | `simpleAttributes` | `attributes` | `companyAddress2` | `cm:companyaddress2` | Mapping of Keycloak profile field `companyAddress2` to Alfresco property |
| `userMapper` | `simpleAttributes` | `attributes` | `companyAddress3` | `cm:companyaddress3` | Mapping of Keycloak profile field `companyAddress3` to Alfresco property |
| `userMapper` | `simpleAttributes` | `attributes` | `companyPostCode` | `cm:companypostcode` | Mapping of Keycloak profile field `companyPostCode` to Alfresco property |
| `userMapper` | `simpleAttributes` | `attributes` | `companyTelephone` | `cm:companytelephone` | Mapping of Keycloak profile field `companyTelephone` to Alfresco property |
| `userMapper` | `simpleAttributes` | `attributes` | `companyFax` | `cm:companyfax` | Mapping of Keycloak profile field `companyFax` to Alfresco property |
| `userMapper` | `simpleAttributes` | `attributes` | `companyEmail` | `cm:companyemail` | Mapping of Keycloak profile field `companyEmail` to Alfresco property |
| `groupMapper` | `simpleAttributes` | `enabled` |  | `true` | Flag determining whether the `simpleAttributes` group mapper is enabled |
| `groupMapper` | `simpleAttributes` | `mapNull` |  | `true` | Flag determining whether `null` values should still be mapped to the corresponding group property - if disabled, mapping of group properties will not remove previously mapped values from Alfresco group nodes if the value has been removed without replacement in Keycloak |

## Role Mapping Properties

### High-Level

The following role mapping configuration properties are supported by the subsystem. All property keys in the table are listed without the common `keycloak.roles.` key prefix.

| Property | Default Value | Description |
| --- | ---: | --- |
| `user` |  | Name of a user account to be used to perform role-related calls to Keycloak - if not set, the subsystem will use the configured adapter client credentials to use the service account of the client (service account must have been enabled / set up in Keycloak) |
| `password` |  | Password for the user account to be used to perform role-related calls to Keycloak|
| `requiredClientScopes` |  | Comma-separated list of required client scopes to be requested for the Keycloak token used for authentication on Keycloak API - this may be necessary if an optional client scope has been configured to include/map the required `realm-management` client roles + audience used in Keycloak for access checking |
| `mapRoles` | `true` | Flag determining whether role mapping is enabled |
| `mapRealmRoles` | `true` | Flag determining whether roles in the context of the Keycloak realm should be mapped |
| `mapResourceRoles` | `true` | Flag determining whether roles in the context of the configured Keycloak client should be mapped |
| `upperCaseRoles` | `true` | Flag determining whether authority names mapped for roles should always be upper-cased regardless of the case in Keycloak |

### Technical - Role Name Filters / Mappers

The following technical role mapping configuration properties are supported by the subsystem to control which names should be mapped and to which Alfresco authority names. Properties in the table use the key patterns `keycloak.roles.<category>.<type>.property.<property>` or `keycloak.roles.<category>.<type>.property.<property>.map.<subKey>`.

| Category | Type | Property | Sub-Key | Default Value | Description |
| --- | --- | --- | --- | ---: | --- |
| `realmFilter` | `pattern` | `forbiddenRoleNamePatterns.list.csv` |  | `offline_access,uma_authorization` | Comma-separated list of Keycloak realm roles that are not to be mapped |
| `realmMapper` | `static` | `nameMappings` | `user` | `ROLE_KEYCLOAK_USER` | Name of the authority for a default Keycloak `user` role, effectively allowing easy identification of Keycloak-authenticated users |
| `realmMapper` | `prefix` | `prefix` |  | `ROLE_KEYCLOAK_${keycloak.adapter.realm}_` | Common prefix of authority names mapped from roles of the realm |
| `resourceMapper` | `default.static` | `nameMappings` | `admin` | `ROLE_ADMINISTRATOR` | Alfresco authority name to use for a client-specific `admin` role in Keycloak |
| `resourceMapper` | `default.static` | `nameMappings` | `guest` | `ROLE_GUEST` | Alfresco authority name to use for a client-specific `guest` role in Keycloak |
| `resourceMapper` | `default.static` | `nameMappings` | `model-admin` | `GROUP_MODEL_ADMINISTRATORS` | Alfresco authority name to use for a client-specific `model-admin` role in Keycloak |
| `resourceMapper` | `default.static` | `nameMappings` | `search-admin` | `GROUP_SEARCH_ADMINISTRATORS` | Alfresco authority name to use for a client-specific `search-admin` role in Keycloak |
| `resourceMapper` | `default.static` | `nameMappings` | `site-admin` | `GROUP_SITE_ADMINISTRATORS` | Alfresco authority name to use for a client-specific `site-admin` role in Keycloak |
| `resourceMapper` | `default.prefix` | `prefix` |  | `ROLE_KEYCLOAK_${keycloak.adapter.realm}_${keycloak.adapter.resource}_` | Common prefix of authority names mapped from client-specific roles (unless already mapped via `default.static`) |

### Technical - Role Service

The following technical role mapping configuration properties are supported by the subsystem for determining how roles are to be exposed via its `RoleService` API, e.g. to be used in Share for permission management. All property keys in the table are listed without the common `keycloak.roles.roleService.impl.property.` key prefix.

| Property | Default Value | Description |
| --- | ---: | --- |
| `hiddenMappedRoles.list.csv` | (too long) | Comma-separated list of Alfresco authority names which should not be exposed even if the names have been mapped from Keycloak roles |

### Technical - Session Caches

In order to support Keycloak back-channel logout / session invalidation, the Repository subsystem uses custom Alfresco caches to map HTTP and SSO session IDs. Additionally, a custom cache is used to map Keycloak access tokens for authentication tickets that have been established by simple user + password authentication in order to refresh them when necessary / possible, and map the relevant roles from the token into the users authorisation context on each subsequent request. The caches added by the addon can be configured just like any other cache in Alfresco. The names / configuration key prefixes for these caches are:

- `cache.acosix-keycloak.ssoToSessionCache`
- `cache.acosix-keycloak.sessionToSsoCache`
- `cache.acosix-keycloak.principalToSessionCache`
- `cache.acosix-keycloak.sessionToPrincipalCache`
- `cache.acosix-keycloak.ticketTokenCache`

By default, all caches have been configured to use a `maxItems` value of `10000`, and are set to be distributed in case either Alfresco Enterprise or the aldica addon is used to enable distributed caching.