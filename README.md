[![Build Status](https://travis-ci.org/Acosix/alfresco-keycloak.svg?branch=master)](https://travis-ci.org/Acosix/alfresco-keycloak)

# About

This addon aims to provide a Keycloak-related extensions / customisations to the out-of-the-box Alfresco authentication and authorization functionalities for the Alfresco Repository and Share tiers.

## Compatbility

This module is built to be compatible with Alfresco 6.0 and above. It may be used on either Community or Enterprise Edition.

## Features

At this time, only the Share sub-module of this project provides a feature enhancement.

The Share sub-module provides a Keycloak-based filter and customisations that support:

- enhancement of the login dialog to allow users to perform an external authentication via a Keycloak server as an alternative to the password-based login
- enforcement of an external authentication via a Keycloak server for all users via a SSO filter enhancement
- back-channel logout and other operations actively initiated by a Keycloak server, e.g. invalidating all authentication tokens issued after a specific point in time
- active logout which also logs out the user centrally on the Keycloak server

# Build

This project uses a Maven build using templates from the [Acosix Alfresco Maven](https://github.com/Acosix/alfresco-maven) project and produces module AMPs, regular Java *classes* JARs, JavaDoc and source attachment JARs, as well as installable (Simple Alfresco Module) JAR artifacts for the Alfresco Content Services and Share extensions. If the installable JAR artifacts are used for installing this module, developers / users are advised to consult the 'Dependencies' section of this README.

## Maven toolchains

By inheritance from the Acosix Alfresco Maven framework, this project uses the [Maven Toolchains plugin](http://maven.apache.org/plugins/maven-toolchains-plugin/) to allow potential cross-compilation against different Java versions. This plugin is used to avoid potentially inconsistent compiler and library versions compared to when only the source/target compiler options of the Maven compiler plugin are set, which (as an example) has caused issues with some Alfresco releases in the past where Alfresco compiled for Java 7 using the Java 8 libraries.
In order to build the project it is necessary to provide a basic toolchain configuration via the user specific Maven configuration home (usually ~/.m2/). That file (toolchains.xml) only needs to list the path to a compatible JDK for the Java version required by this project. The following is a sample file defining a Java 7 and 8 development kit.

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
      <jdkHome>C:\Program Files\Java\jdk1.8.0_112</jdkHome>
    </configuration>
  </toolchain>
  <toolchain>
    <type>jdk</type>
    <provides>
      <version>1.7</version>
      <vendor>oracle</vendor>
    </provides>
    <configuration>
      <jdkHome>C:\Program Files\Java\jdk1.7.0_80</jdkHome>
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

This project currently does not contain any integration tests, as a proper setup which includes Keycloak has not yet been achieved.

## Dependencies

This module depends on the following projects / libraries:

- various [Keycloak](https://github.com/keycloak/keycloak) adapter and client libraries (Apache License, Version 2.0)
    - keycloak-adapter-core
    - keycloak-servlet-adapter-spi
    - keycloak-servlet-filter-adapter
    - keycloak-authz-client
- Acosix Alfresco Utility (Apache License, Version 2.0) - core extension

The Share AMP of this project includes all the Keycloak library JARs that the extension depends on. The Acosix Alfresco Utility project provides the core extension for Alfresco Content Services as a separate artifact from the full module, which needs to be installed in Alfresco Content Services before the AMP of this project can be installed.

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