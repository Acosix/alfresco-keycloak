[![Build Status](https://travis-ci.org/Acosix/alfresco-keycloak.svg?branch=master)](https://travis-ci.org/Acosix/alfresco-keycloak)

# About

This addon aims to provide a Keycloak-related extensions / customisations to the out-of-the-box Alfresco authentication and authorisation functionalities for the Alfresco Repository and Share tiers.

## Compatbility

This module is built to be compatible with Alfresco 6.0 and above. It may be used on either Community or Enterprise Edition.

## Features

The Repository sub-module provides a custom authentication subsystem dealing with Keycloak (separate to Alfresco's default `identity-service`) and customisations which support:

- user + password login via `AuthenticationService.authenticate` / `AuthenticationComponent.authenticate`
- `Bearer` token authentication using a client-obtained access token
- redirection to Keycloak login UI and OIDC authentication flow (SSO), if client not already authenticated in session, no pre-emptive details provided in request and API requires authentication
- mapping of person properties on authentication from user access / identity token
- mapping of authorities from user access token (for purpose of permission / role checks)
- handling Keycloak back-channel requests
    - back-channel logout requests from Keycloak (i.e. SSO including "single sign-out")
    - bulk-invalidation of access tokens issued before a certain point in time
    - availability test / basic validation
    - JWKS (public key) update
- active user / group synchronisation against Keycloak's directory (which may include users / groups synchronised from multiple federated directories)
- Java service, JavaScript service and web script to expose roles mapped from Keycloak for retrieval (e.g. to be used in permission management)

The Share sub-module provides a Keycloak-based filter and customisations that support:

- redirection to Keycloak login UI and OIDC authentication flow (SSO), if client not already authenticated in session, no pre-emptive details provided in request and SSO authentication required/enforced via configuration
- enhancement of the login dialog to allow users to perform an alternative, external authentication via Keycloak
- handling Keycloak back-channel requests
    - back-channel logout requests from Keycloak (i.e. SSO including "single sign-out")
    - bulk-invalidation of access tokens issued before a certain point in time
    - availability test / basic validation
    - JWKS (public key) update
- Share logout action triggering a Keycloak logout (logging user out of other applications handled by Keycloak if those support Keycloak back-channel logout requests)
- [RFC 8693 OAuth 2.0 Token Exchange](https://tools.ietf.org/html/rfc8693) (a [preview functionality in Keycloak](https://www.keycloak.org/docs/latest/securing_apps/#_token-exchange) to properly delegate the Share-tier authentication to the Repository, if signed on via Keycloak SSO

All authentication functionality of this addon is based on OpenID Connect. Though Keycloak does support SAML clients, no support was implemented to have Alfresco act as a SAML client against Keycloak as an alternative to OpenID Connect client behaviour.

# Configuration

The configuration of both the Keycloak server and this module offer a large number of properties to adjust, and various modes of operation. Therefore, the following sub-documents have been created to provide details and guides:

- [Getting Started (Simple Configuration)](./docs/Simple-Configuration.md)
- Repository Configuration Reference
    - [Keycloak Subsystem](./docs/Reference-Repository-Subsystem.md)
    - [Keycloak Adapter](./docs/Reference-Adapter.md)
    - [Extension API](./docs/Reference-Repository-Extension.md)
- [Share Configuration Reference](./docs/Reference-Repository.md)

# Build

This project uses a Maven build using templates from the [Acosix Alfresco Maven](https://github.com/Acosix/alfresco-maven) project and produces module AMPs, regular Java *classes* JARs, JavaDoc and source attachment JARs, as well as installable (Simple Alfresco Module) JAR artifacts for the Alfresco Content Services and Share extensions. If the installable JAR artifacts are used for installing this module, developers / users are advised to consult the 'Dependencies' section of this README.

## Maven toolchains

By inheritance from the Acosix Alfresco Maven framework, this project uses the [Maven Toolchains plugin](http://maven.apache.org/plugins/maven-toolchains-plugin/) to allow potential cross-compilation against different Java versions. This plugin is used to avoid potentially inconsistent compiler and library versions compared to when only the source/target compiler options of the Maven compiler plugin are set, which (as an example) has caused issues with some Alfresco releases in the past where Alfresco compiled for Java 7 using the Java 8 libraries.
In order to build the project it is necessary to provide a basic toolchain configuration via the user specific Maven configuration home (usually ~/.m2/). That file (toolchains.xml) only needs to list the path to a compatible JDK for the Java version required by this project. The following is a sample file defining a Java 8 and 11 development kit.

```xml
<?xml version='1.0' encoding='UTF-8'?>
<toolchains xmlns="http://maven.apache.org/TOOLCHAINS/1.1.0" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:schemaLocation="http://maven.apache.org/TOOLCHAINS/1.1.0 http://maven.apache.org/xsd/toolchains-1.1.0.xsd">
  <toolchain>
    <type>jdk</type>
    <provides>
      <version>1.8</version>
      <vendor>oracle</vendor>
    </provides>
    <configuration>
      <jdkHome>C:\Program Files\Java\jdk1.8.0_231</jdkHome>
    </configuration>
  </toolchain>
  <toolchain>
    <type>jdk</type>
    <provides>
      <version>1.11</version>
      <vendor>oracle</vendor>
      <id>openjdk11</id>
    </provides>
    <configuration>
      <jdkHome>C:\Program Files\Java\jdk-11.0.2</jdkHome>
    </configuration>
  </toolchain>
</toolchains>
```

The master branch requires Java 8.

## Docker-based integration tests

In a default build using ```mvn clean install```, this project will build the extension for Alfresco Content Services, executing regular unit-tests without running integration tests. The integration tests of this project are based on Docker and require a Docker engine to run the necessary components (PostgreSQL database as well as Alfresco Content Services). Since a Docker engine may not be available in all environments of interested community members / collaborators, the integration tests have been made optional. A full build, including integration tests, can be run by executing

```
mvn clean install -Ddocker.tests.enabled=true
```

This project currently does not yet contain any specific integration tests but does use integration tests to verify Alfresco correctly starts up with the addon installed.

## Dependencies

This module depends on the following projects / libraries:

- various [Keycloak](https://github.com/keycloak/keycloak) adapter and client libraries (Apache License, Version 2.0)
    - keycloak-adapter-core
    - keycloak-servlet-adapter-spi
    - keycloak-servlet-filter-adapter
    - keycloak-authz-client
- Acosix Alfresco Utility (Apache License, Version 2.0) - core extension

All Keycloak dependencies are aggregated into single uber-JAR / shaded dependency library for the Repository and Share respectively. This aggregation is handled via the sub-modules `repository-dependencies` and `share-dependencies`. This has been done to isolate this addon from whatever version of Keycloak libraries Alfresco pre-packages to support its `identity-service` authentication subsystem. These aggregated libraries are included in the respective AMPs of this project and only need to be installed separately if the simple JAR deployment method is used to install the modules of this addon.

The Acosix Alfresco Utility project provides the core extension for Alfresco Content Services as a separate artifact from the full module, which needs to be installed in Alfresco Content Services before the AMP of this project can be installed.

When the installable JAR produced by the build of this project is used for installation, the developer / user is responsible to either manually install all the required components / libraries provided by the listed projects, or use a build system to collect all relevant direct / transitive dependencies.
**Note**: The Acosix Alfresco Utility project is also built using templates from the Acosix Alfresco Maven project, and as such produces similar artifacts. Automatic resolution and collection of (transitive) dependencies using Maven / Gradle will resolve the Java *classes* JAR as a dependency, and **not** the installable (Simple Alfresco Module) variant. It is recommended to exclude Acosix Alfresco Utility from transitive resolution and instead include it directly / explicitly.

## Using SNAPSHOT builds

In order to use a pre-built SNAPSHOT artifact published to the Open Source Sonatype Repository Hosting site, the artifact repository may need to be added to the POM, global settings.xml or an artifact repository proxy server. The following is the XML snippet for inclusion in a POM file.

```xml
<repositories>
    <repository>
        <id>ossrh</id>
        <url>https://oss.sonatype.org/content/repositories/snapshots</url>
        <snapshots>
            <enabled>true</enabled>
        </snapshots>
    </repository>
</repositories>
```