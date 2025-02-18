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
package de.acosix.alfresco.keycloak.repo.authentication;

import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.alfresco.service.cmr.security.AuthorityType;
import org.alfresco.util.ParameterCheck;
import org.alfresco.util.PropertyCheck;
import org.keycloak.representations.AccessToken;
import org.keycloak.representations.AccessToken.Access;
import org.keycloak.representations.adapters.config.AdapterConfig;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.InitializingBean;

import de.acosix.alfresco.keycloak.repo.roles.RoleNameFilter;
import de.acosix.alfresco.keycloak.repo.roles.RoleNameMapper;

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

    protected AdapterConfig adapterConfig;

    protected boolean processRealmRoles;

    protected boolean processResourceRoles;

    protected RoleNameFilter realmRoleNameFilter;

    protected RoleNameMapper realmRoleNameMapper;

    protected RoleNameFilter defaultResourceRoleNameFilter;

    protected RoleNameMapper defaultResourceRoleNameMapper;

    protected Map<String, RoleNameFilter> resourceRoleNameFilter;

    protected Map<String, RoleNameMapper> resourceRoleNameMapper;

    /**
     *
     * {@inheritDoc}
     */
    @Override
    public void afterPropertiesSet()
    {
        if (this.enabled && this.processRealmRoles)
        {
            PropertyCheck.mandatory(this, "realmRoleNameMapper", this.realmRoleNameMapper);
        }

        if (this.enabled && this.processResourceRoles)
        {
            PropertyCheck.mandatory(this, "adapterConfig", this.adapterConfig);
            PropertyCheck.mandatory(this, "defaultResourceRoleNameMapper", this.defaultResourceRoleNameMapper);

            if (this.resourceRoleNameMapper == null)
            {
                this.resourceRoleNameMapper = new HashMap<>();
            }
            this.resourceRoleNameMapper.put(this.adapterConfig.getResource(), this.defaultResourceRoleNameMapper);

            if (this.defaultResourceRoleNameFilter != null)
            {
                if (this.resourceRoleNameFilter == null)
                {
                    this.resourceRoleNameFilter = new HashMap<>();
                }
                this.resourceRoleNameFilter.put(this.adapterConfig.getResource(), this.defaultResourceRoleNameFilter);
            }
        }
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
     * @param adapterConfig
     *            the adapterConfig to set
     */
    public void setAdapterConfig(final AdapterConfig adapterConfig)
    {
        this.adapterConfig = adapterConfig;
    }

    /**
     * @param processRealmRoles
     *            the processRealmRoles to set
     */
    public void setProcessRealmRoles(final boolean processRealmRoles)
    {
        this.processRealmRoles = processRealmRoles;
    }

    /**
     * @param processResourceRoles
     *            the processResourceRoles to set
     */
    public void setProcessResourceRoles(final boolean processResourceRoles)
    {
        this.processResourceRoles = processResourceRoles;
    }

    /**
     * @param realmRoleNameFilter
     *            the realmRoleNameFilter to set
     */
    public void setRealmRoleNameFilter(final RoleNameFilter realmRoleNameFilter)
    {
        this.realmRoleNameFilter = realmRoleNameFilter;
    }

    /**
     * @param realmRoleNameMapper
     *            the realmRoleNameMapper to set
     */
    public void setRealmRoleNameMapper(final RoleNameMapper realmRoleNameMapper)
    {
        this.realmRoleNameMapper = realmRoleNameMapper;
    }

    /**
     * @param defaultResourceRoleNameFilter
     *            the defaultResourceRoleNameFilter to set
     */
    public void setDefaultResourceRoleNameFilter(final RoleNameFilter defaultResourceRoleNameFilter)
    {
        this.defaultResourceRoleNameFilter = defaultResourceRoleNameFilter;
    }

    /**
     * @param defaultResourceRoleNameMapper
     *            the defaultResourceRoleNameMapper to set
     */
    public void setDefaultResourceRoleNameMapper(final RoleNameMapper defaultResourceRoleNameMapper)
    {
        this.defaultResourceRoleNameMapper = defaultResourceRoleNameMapper;
    }

    /**
     * @param resourceRoleNameFilter
     *            the resourceRoleNameFilter to set
     */
    public void setResourceRoleNameFilter(final Map<String, RoleNameFilter> resourceRoleNameFilter)
    {
        this.resourceRoleNameFilter = resourceRoleNameFilter;
    }

    /**
     * @param resourceRoleNameMapper
     *            the resourceRoleNameMapper to set
     */
    public void setResourceRoleNameMapper(final Map<String, RoleNameMapper> resourceRoleNameMapper)
    {
        this.resourceRoleNameMapper = resourceRoleNameMapper;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Set<String> extractAuthorities(final AccessToken accessToken)
    {
        final Set<String> authorities;

        if (this.enabled)
        {
            if (this.processRealmRoles || this.processResourceRoles)
            {
                authorities = new HashSet<>();

                if (this.processRealmRoles)
                {
                    final Access realmAccess = accessToken.getRealmAccess();
                    if (realmAccess != null)
                    {
                        LOGGER.debug("Mapping authorities from realm access");

                        final Set<String> realmAuthorites = this.processAccess(realmAccess, this.realmRoleNameFilter,
                                this.realmRoleNameMapper);

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

                if (this.processResourceRoles)
                {
                    final Map<String, Access> resourceAccess = accessToken.getResourceAccess();

                    resourceAccess.forEach((r, a) -> {
                        if (this.resourceRoleNameMapper.containsKey(r))
                        {
                            LOGGER.debug("Mapping authorities from resource access on {}", r);

                            final Set<String> resourceAuthorites = this.processAccess(a, this.resourceRoleNameFilter.get(r),
                                    this.resourceRoleNameMapper.get(r));

                            LOGGER.debug("Mapped authorities from resource access on {}: {}", r, resourceAuthorites);

                            authorities.addAll(resourceAuthorites);
                        }
                    });
                }
                else
                {
                    LOGGER.debug("Mapping authorities from resource access is not enabled");
                }
            }
            else
            {
                LOGGER.debug("Mapping authorities is not enabled for either realm or resource access");
                authorities = Collections.emptySet();
            }
        }
        else
        {
            LOGGER.debug("Mapping authorities from access token is not enabled");
            authorities = Collections.emptySet();
        }

        return authorities;
    }

    /**
     * Maps / extracts authorities from a Keycloak access representation.
     *
     * @param access
     *            the access representation component of an access token
     * @param roleNameFilter
     *            the role name filter to use or {@code null} if no filtering should be applied
     * @param roleNameMapper
     *            the role name mapper - can never be {@code null}
     * @return the authorities mapped / extracted from the access representation
     */
    protected Set<String> processAccess(final Access access, final RoleNameFilter roleNameFilter, final RoleNameMapper roleNameMapper)
    {
        ParameterCheck.mandatory("access", access);
        ParameterCheck.mandatory("roleNameMapper", roleNameMapper);

        final Set<String> authorities;

        final Set<String> accessRoles = access.getRoles();
        if (accessRoles != null && !accessRoles.isEmpty())
        {
            LOGGER.debug("Mapping / filtering access roles {}", accessRoles);

            Stream<String> roleStream = accessRoles.stream();
            if (roleNameFilter != null)
            {
                roleStream = roleStream.filter(roleNameFilter::isRoleExposed);
            }
            authorities = roleStream.map(roleNameMapper::mapRoleName).filter(Optional::isPresent).map(Optional::get).map(r -> {
                final AuthorityType authorityType = AuthorityType.getAuthorityType(r);
                String result = r;
                if (authorityType != AuthorityType.GROUP && authorityType != AuthorityType.ROLE)
                {
                    result = AuthorityType.ROLE.getPrefixString() + r;
                }
                return result;
            }).collect(Collectors.toSet());
        }
        else
        {
            LOGGER.debug("Access representation contains no roles");
            authorities = Collections.emptySet();
        }

        return authorities;
    }
}
