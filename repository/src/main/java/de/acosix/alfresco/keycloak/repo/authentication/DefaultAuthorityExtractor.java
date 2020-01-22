/*
 * Copyright 2019 - 2020 Acosix GmbH
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
package de.acosix.alfresco.keycloak.repo.authentication;

import java.util.Collections;
import java.util.EnumSet;
import java.util.HashSet;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.function.Function;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.alfresco.service.cmr.security.AuthorityType;
import org.alfresco.util.PropertyCheck;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.InitializingBean;

import de.acosix.alfresco.keycloak.repo.deps.keycloak.representations.AccessToken;
import de.acosix.alfresco.keycloak.repo.deps.keycloak.representations.AccessToken.Access;
import de.acosix.alfresco.keycloak.repo.deps.keycloak.representations.adapters.config.AdapterConfig;

/**
 * Instances of this class provide a generalised default authority mapping / extraction logic for Keycloak authenticated users. The mapping
 * / extraction processes both realm and client- / resource-specific roles, and provides configurable authority name transformation (e.g.
 * consistent casing, authority type prefixes, potential subsystem prefixes for differentiation).
 *
 * @author Axel Faust
 */
public class DefaultAuthorityExtractor implements InitializingBean, AuthorityExtractor
{

    private static final Logger LOGGER = LoggerFactory.getLogger(DefaultAuthorityExtractor.class);

    protected boolean enabled;

    protected boolean processRealmAccess;

    protected boolean processResourceAccess;

    protected Map<String, String> realmAccessExplicitMappings;

    protected Map<String, String> resourceAccessExplicitMappings;

    protected AuthorityType realmAccessAuthorityType;

    protected AuthorityType resourceAccessAuthorityType;

    protected String realmAccessAuthorityNamePrefix;

    protected String resourceAccessAuthorityNamePrefix;

    protected boolean applyRealmAccessAuthorityCapitalisation;

    protected boolean applyResourceAccessAuthorityCapitalisation;

    protected String realmAccessAuthorityCapitalisationLocale;

    protected String resourceAccessAuthorityCapitalisationLocale;

    protected Locale effectiveRealmAccessAuthorityCapitalisationLocale;

    protected Locale effectiveResourceAccessAuthorityCapitalisationLocale;

    protected AdapterConfig adapterConfig;

    /**
     *
     * {@inheritDoc}
     */
    @Override
    public void afterPropertiesSet()
    {
        PropertyCheck.mandatory(this, "realmAccessAuthorityType", this.realmAccessAuthorityType);
        PropertyCheck.mandatory(this, "resourceAccessAuthorityType", this.resourceAccessAuthorityType);
        PropertyCheck.mandatory(this, "realmAccessAuthorityNamePrefix", this.realmAccessAuthorityNamePrefix);
        PropertyCheck.mandatory(this, "resourceAccessAuthorityNamePrefix", this.resourceAccessAuthorityNamePrefix);
        PropertyCheck.mandatory(this, "adapterConfig", this.adapterConfig);

        final Set<AuthorityType> allowedTypes = EnumSet.of(AuthorityType.ROLE, AuthorityType.GROUP);
        if (!allowedTypes.contains(this.realmAccessAuthorityType))
        {
            throw new IllegalStateException("Only ROLE and GROUP authority types are allowed for realmAccessAuthorityType");
        }
        if (!allowedTypes.contains(this.resourceAccessAuthorityType))
        {
            throw new IllegalStateException("Only ROLE and GROUP authority types are allowed for resourceAccessAuthorityType");
        }

        final Function<String, Locale> localeConversion = capitalisationLocale -> {
            final Locale locale;
            if (capitalisationLocale != null)
            {
                final String[] localeFragments = capitalisationLocale.split("[_\\-]");
                if (localeFragments.length >= 3)
                {
                    locale = new Locale(localeFragments[0], localeFragments[1], localeFragments[2]);
                }
                else if (localeFragments.length >= 2)
                {
                    locale = new Locale(localeFragments[0], localeFragments[1]);
                }
                else
                {
                    locale = new Locale(localeFragments[0]);
                }
            }
            else
            {
                locale = Locale.getDefault();
            }
            return locale;
        };
        this.effectiveRealmAccessAuthorityCapitalisationLocale = localeConversion.apply(this.realmAccessAuthorityCapitalisationLocale);
        this.effectiveResourceAccessAuthorityCapitalisationLocale = localeConversion
                .apply(this.resourceAccessAuthorityCapitalisationLocale);
    }

    /**
     * @param enabled
     *            the enabled to set
     */
    public void setEnabled(final boolean enabled)
    {
        this.enabled = enabled;
    }

    /**
     * @param processRealmAccess
     *            the processRealmAccess to set
     */
    public void setProcessRealmAccess(final boolean processRealmAccess)
    {
        this.processRealmAccess = processRealmAccess;
    }

    /**
     * @param processResourceAccess
     *            the processResourceAccess to set
     */
    public void setProcessResourceAccess(final boolean processResourceAccess)
    {
        this.processResourceAccess = processResourceAccess;
    }

    /**
     * @param realmAccessExplicitMappings
     *            the realmAccessExplicitMappings to set
     */
    public void setRealmAccessExplicitMappings(final Map<String, String> realmAccessExplicitMappings)
    {
        this.realmAccessExplicitMappings = realmAccessExplicitMappings;
    }

    /**
     * @param resourceAccessExplicitMappings
     *            the resourceAccessExplicitMappings to set
     */
    public void setResourceAccessExplicitMappings(final Map<String, String> resourceAccessExplicitMappings)
    {
        this.resourceAccessExplicitMappings = resourceAccessExplicitMappings;
    }

    /**
     * @param realmAccessAuthorityType
     *            the realmAccessAuthorityType to set
     */
    public void setRealmAccessAuthorityType(final AuthorityType realmAccessAuthorityType)
    {
        this.realmAccessAuthorityType = realmAccessAuthorityType;
    }

    /**
     * @param resourceAccessAuthorityType
     *            the resourceAccessAuthorityType to set
     */
    public void setResourceAccessAuthorityType(final AuthorityType resourceAccessAuthorityType)
    {
        this.resourceAccessAuthorityType = resourceAccessAuthorityType;
    }

    /**
     * @param realmAccessAuthorityNamePrefix
     *            the realmAccessAuthorityNamePrefix to set
     */
    public void setRealmAccessAuthorityNamePrefix(final String realmAccessAuthorityNamePrefix)
    {
        this.realmAccessAuthorityNamePrefix = realmAccessAuthorityNamePrefix;
    }

    /**
     * @param resourceAccessAuthorityNamePrefix
     *            the resourceAccessAuthorityNamePrefix to set
     */
    public void setResourceAccessAuthorityNamePrefix(final String resourceAccessAuthorityNamePrefix)
    {
        this.resourceAccessAuthorityNamePrefix = resourceAccessAuthorityNamePrefix;
    }

    /**
     * @param applyRealmAccessAuthorityCapitalisation
     *            the applyRealmAccessAuthorityCapitalisation to set
     */
    public void setApplyRealmAccessAuthorityCapitalisation(final boolean applyRealmAccessAuthorityCapitalisation)
    {
        this.applyRealmAccessAuthorityCapitalisation = applyRealmAccessAuthorityCapitalisation;
    }

    /**
     * @param applyResourceAccessAuthorityCapitalisation
     *            the applyResourceAccessAuthorityCapitalisation to set
     */
    public void setApplyResourceAccessAuthorityCapitalisation(final boolean applyResourceAccessAuthorityCapitalisation)
    {
        this.applyResourceAccessAuthorityCapitalisation = applyResourceAccessAuthorityCapitalisation;
    }

    /**
     * @param realmAccessAuthorityCapitalisationLocale
     *            the realmAccessAuthorityCapitalisationLocale to set
     */
    public void setRealmAccessAuthorityCapitalisationLocale(final String realmAccessAuthorityCapitalisationLocale)
    {
        this.realmAccessAuthorityCapitalisationLocale = realmAccessAuthorityCapitalisationLocale;
    }

    /**
     * @param resourceAccessAuthorityCapitalisationLocale
     *            the resourceAccessAuthorityCapitalisationLocale to set
     */
    public void setResourceAccessAuthorityCapitalisationLocale(final String resourceAccessAuthorityCapitalisationLocale)
    {
        this.resourceAccessAuthorityCapitalisationLocale = resourceAccessAuthorityCapitalisationLocale;
    }

    /**
     * @param adapterConfig
     *            the adapterConfig to set
     */
    public void setAdapterConfig(final AdapterConfig adapterConfig)
    {
        this.adapterConfig = adapterConfig;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Set<String> extractAuthorities(final AccessToken accessToken)
    {
        Set<String> authorities = Collections.emptySet();

        if (this.enabled)
        {
            if (this.processRealmAccess || this.processResourceAccess)
            {
                authorities = new HashSet<>();

                if (this.processRealmAccess)
                {
                    final Access realmAccess = accessToken.getRealmAccess();
                    if (realmAccess != null)
                    {
                        LOGGER.debug("Mapping authorities from realm access");

                        final Set<String> realmAuthorites = this.processAccess(realmAccess, this.realmAccessExplicitMappings,
                                this.realmAccessAuthorityType, this.realmAccessAuthorityNamePrefix,
                                this.applyRealmAccessAuthorityCapitalisation, this.effectiveRealmAccessAuthorityCapitalisationLocale);

                        LOGGER.debug("Mapped authorities from realm access: {}", realmAuthorites);

                        authorities.addAll(realmAuthorites);
                    }
                    else
                    {
                        LOGGER.debug("No realm access provided in access token");
                    }
                }
                else
                {
                    LOGGER.debug("Mapping authorities from realm access is not enabled");
                }

                if (this.processResourceAccess)
                {
                    final String resource = this.adapterConfig.getResource();
                    final Access resourceAccess = accessToken.getResourceAccess(resource);
                    if (resourceAccess != null)
                    {
                        LOGGER.debug("Mapping authorities from resource access on {}", resource);

                        final Set<String> resourceAuthorites = this.processAccess(resourceAccess, this.resourceAccessExplicitMappings,
                                this.resourceAccessAuthorityType, this.resourceAccessAuthorityNamePrefix,
                                this.applyResourceAccessAuthorityCapitalisation, this.effectiveResourceAccessAuthorityCapitalisationLocale);

                        LOGGER.debug("Mapped authorities from resource access on {}: {}", resource, resourceAuthorites);

                        authorities.addAll(resourceAuthorites);
                    }
                    else
                    {
                        LOGGER.debug("No resource access for {} provided in access token", resource);
                    }
                }
                else
                {
                    LOGGER.debug("Mapping authorities from resource access is not enabled");
                }
            }
            else
            {
                LOGGER.debug("Mapping authorities is not enabled for either realm or resource access");
            }
        }
        else
        {
            LOGGER.debug("Mapping authorities from access token is not enabled");
        }

        return authorities;
    }

    /**
     * Maps / extracts authorities from a Keycloak access representation.
     *
     * @param access
     *            the access representation component of an access token
     * @param explicitMappings
     *            the explicit mappings of roles to authorities to consider - an explicit mapping for a role overrides the default mapping
     *            handling for that role only
     * @param authorityType
     *            the authority type to use for mapped / extracted authorities
     * @param prefix
     *            the static authority name prefix to use for mapped / extracted authorities
     * @param capitalisation
     *            {@code true} if authorities should be standardised on fully capitalised names, {@code false} if names should be left as
     *            mapped from the access representation
     * @param capitalisationLocale
     *            the locale to use when capitalising authority names
     * @return the authorities mapped / extracted from the access representation
     */
    protected Set<String> processAccess(final Access access, final Map<String, String> explicitMappings, final AuthorityType authorityType,
            final String prefix, final boolean capitalisation, final Locale capitalisationLocale)
    {
        final Set<String> authorities;

        final Set<String> roles = access.getRoles();
        if (roles != null && !roles.isEmpty())
        {
            LOGGER.debug("Access representation contains roles {}", roles);

            Stream<String> rolesStream = roles.stream();
            if (explicitMappings != null && !explicitMappings.isEmpty())
            {
                LOGGER.debug("Explicit mappings for roles have been provided");
                rolesStream = rolesStream.filter(r -> !explicitMappings.containsKey(r));
            }

            if (prefix != null && !prefix.isEmpty())
            {
                rolesStream = rolesStream.map(r -> prefix + "_" + r);
            }
            rolesStream = rolesStream.map(r -> authorityType.getPrefixString() + r);
            if (capitalisation)
            {

                rolesStream = rolesStream.map(r -> r.toUpperCase(capitalisationLocale));
            }
            authorities = rolesStream.collect(Collectors.toSet());
            LOGGER.debug("Generically mapped authorities: {}", authorities);

            if (explicitMappings != null && !explicitMappings.isEmpty())
            {
                final Set<String> explicitlyMappedAuthorities = roles.stream().filter(explicitMappings::containsKey)
                        .map(explicitMappings::get).collect(Collectors.toSet());
                LOGGER.debug("Explicitly mapped authorities: {}", explicitlyMappedAuthorities);
                authorities.addAll(explicitlyMappedAuthorities);
            }
        }
        else
        {
            LOGGER.debug("Access representation contains no roles");

            authorities = Collections.emptySet();
        }

        return authorities;
    }
}
