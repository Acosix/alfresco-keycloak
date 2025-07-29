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
package de.acosix.alfresco.keycloak.repo.roles;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.locks.ReentrantReadWriteLock;
import java.util.function.BinaryOperator;
import java.util.function.Consumer;
import java.util.function.UnaryOperator;
import java.util.regex.Pattern;

import org.alfresco.service.cmr.security.AuthorityType;
import org.alfresco.util.ParameterCheck;
import org.alfresco.util.PropertyCheck;
import org.keycloak.representations.adapters.config.AdapterConfig;
import org.keycloak.representations.idm.RoleRepresentation;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.InitializingBean;

import de.acosix.alfresco.keycloak.repo.client.RolesClient;

/**
 *
 * @author Axel Faust
 */
public class RoleServiceImpl implements RoleService, InitializingBean
{

    private static final Logger LOGGER = LoggerFactory.getLogger(RoleServiceImpl.class);

    private static final String SENTINEL = RoleServiceImpl.class.getName();

    protected AdapterConfig adapterConfig;

    protected RolesClient rolesClient;

    protected boolean enabled;

    protected boolean processRealmRoles;

    protected boolean processResourceRoles;

    protected RoleNameFilter realmRoleNameFilter;

    protected RoleNameMapper realmRoleNameMapper;

    protected RoleNameFilter defaultResourceRoleNameFilter;

    protected RoleNameMapper defaultResourceRoleNameMapper;

    protected Map<String, RoleNameFilter> resourceRoleNameFilter;

    protected Map<String, RoleNameMapper> resourceRoleNameMapper;

    protected List<String> hiddenMappedRoles;

    protected final Map<String, String> clientIdByResourceName = new HashMap<>();

    protected final ReentrantReadWriteLock clientIdByResourceNameLock = new ReentrantReadWriteLock(true);

    /**
     *
     * {@inheritDoc}
     */
    @Override
    public void afterPropertiesSet()
    {
        PropertyCheck.mandatory(this, "rolesClient", this.rolesClient);

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
     * @param rolesClient
     *     the rolesClient to set
     */
    public void setRolesClient(final RolesClient rolesClient)
    {
        this.rolesClient = rolesClient;
    }

    /**
     * @param adapterConfig
     *     the adapterConfig to set
     */
    public void setAdapterConfig(final AdapterConfig adapterConfig)
    {
        this.adapterConfig = adapterConfig;
    }

    /**
     * @param enabled
     *     the enabled to set
     */
    public void setEnabled(final boolean enabled)
    {
        this.enabled = enabled;
    }

    /**
     * @param processRealmRoles
     *     the processRealmRoles to set
     */
    public void setProcessRealmRoles(final boolean processRealmRoles)
    {
        this.processRealmRoles = processRealmRoles;
    }

    /**
     * @param processResourceRoles
     *     the processResourceRoles to set
     */
    public void setProcessResourceRoles(final boolean processResourceRoles)
    {
        this.processResourceRoles = processResourceRoles;
    }

    /**
     * @param realmRoleNameFilter
     *     the realmRoleNameFilter to set
     */
    public void setRealmRoleNameFilter(final RoleNameFilter realmRoleNameFilter)
    {
        this.realmRoleNameFilter = realmRoleNameFilter;
    }

    /**
     * @param realmRoleNameMapper
     *     the realmRoleNameMapper to set
     */
    public void setRealmRoleNameMapper(final RoleNameMapper realmRoleNameMapper)
    {
        this.realmRoleNameMapper = realmRoleNameMapper;
    }

    /**
     * @param defaultResourceRoleNameFilter
     *     the defaultResourceRoleNameFilter to set
     */
    public void setDefaultResourceRoleNameFilter(final RoleNameFilter defaultResourceRoleNameFilter)
    {
        this.defaultResourceRoleNameFilter = defaultResourceRoleNameFilter;
    }

    /**
     * @param defaultResourceRoleNameMapper
     *     the defaultResourceRoleNameMapper to set
     */
    public void setDefaultResourceRoleNameMapper(final RoleNameMapper defaultResourceRoleNameMapper)
    {
        this.defaultResourceRoleNameMapper = defaultResourceRoleNameMapper;
    }

    /**
     * @param resourceRoleNameFilter
     *     the resourceRoleNameFilter to set
     */
    public void setResourceRoleNameFilter(final Map<String, RoleNameFilter> resourceRoleNameFilter)
    {
        this.resourceRoleNameFilter = resourceRoleNameFilter;
    }

    /**
     * @param resourceRoleNameMapper
     *     the resourceRoleNameMapper to set
     */
    public void setResourceRoleNameMapper(final Map<String, RoleNameMapper> resourceRoleNameMapper)
    {
        this.resourceRoleNameMapper = resourceRoleNameMapper;
    }

    /**
     * @param hiddenMappedRoles
     *     the hiddenMappedRoles to set
     */
    public void setHiddenMappedRoles(final List<String> hiddenMappedRoles)
    {
        this.hiddenMappedRoles = hiddenMappedRoles;
    }

    /**
     *
     * {@inheritDoc}
     */
    @Override
    public List<Role> listRoles()
    {
        return this.doFindRoles(null, false);
    }

    /**
     *
     * {@inheritDoc}
     */
    @Override
    public List<Role> findRoles(final String shortNameFilter)
    {
        ParameterCheck.mandatoryString("shortNameFilter", shortNameFilter);
        return this.doFindRoles(shortNameFilter, false);
    }

    /**
     *
     * {@inheritDoc}
     */
    @Override
    public List<Role> listRoles(final boolean realmOnly)
    {
        return this.doFindRoles(null, realmOnly);
    }

    /**
     *
     * {@inheritDoc}
     */
    @Override
    public List<Role> findRoles(final String shortNameFilter, final boolean realmOnly)
    {
        ParameterCheck.mandatoryString("shortNameFilter", shortNameFilter);
        return this.doFindRoles(shortNameFilter, realmOnly);
    }

    /**
     *
     * {@inheritDoc}
     */
    @Override
    public List<Role> listRoles(final String resourceName)
    {
        ParameterCheck.mandatory("resourceName", resourceName);
        return this.doFindRoles(resourceName, null);
    }

    /**
     *
     * {@inheritDoc}
     */
    @Override
    public List<Role> findRoles(final String resourceName, final String shortNameFilter)
    {
        ParameterCheck.mandatory("resourceName", resourceName);
        ParameterCheck.mandatoryString("shortNameFilter", shortNameFilter);
        return this.doFindRoles(resourceName, shortNameFilter);
    }

    /**
     *
     * {@inheritDoc}
     */
    @Override
    public boolean isMappedFromKeycloak(final String authorityName)
    {
        ParameterCheck.mandatoryString("authorityName", authorityName);

        Optional<String> role = Optional.empty();

        if (this.processRealmRoles)
        {
            role = this.realmRoleNameMapper.mapAuthorityName(authorityName);
        }
        if (this.processResourceRoles)
        {
            final Iterator<String> resourceIterator = this.resourceRoleNameMapper.keySet().iterator();
            while (!role.isPresent() && resourceIterator.hasNext())
            {
                final RoleNameMapper roleNameMapper = this.resourceRoleNameMapper.get(resourceIterator.next());
                role = roleNameMapper.mapAuthorityName(authorityName);
            }
        }
        return role.isPresent();
    }

    /**
     *
     * {@inheritDoc}
     */
    @Override
    public Optional<String> getRoleName(final String authorityName)
    {
        ParameterCheck.mandatoryString("authorityName", authorityName);

        Optional<String> role = Optional.empty();

        if (this.processRealmRoles)
        {
            final UnaryOperator<String> realmRoleResolver = rn -> {
                final Set<String> matchingRoles = new HashSet<>();
                this.rolesClient.processRealmRoles(rn, 0, Integer.MAX_VALUE, roleResult -> {
                    if (roleResult.getName().equalsIgnoreCase(rn))
                    {
                        matchingRoles.add(roleResult.getName());
                    }
                });

                String matchingRole = null;
                if (matchingRoles.size() == 1)
                {
                    matchingRole = matchingRoles.iterator().next();
                }
                else
                {
                    LOGGER.warn("Failed to match apparent Keycloak realm role {} to unique role via admin API", rn);
                }
                return matchingRole;
            };
            role = this.realmRoleNameMapper.mapAuthorityName(authorityName).map(realmRoleResolver);
        }
        if (this.processResourceRoles)
        {
            final BinaryOperator<String> clientRoleResolver = (client, rn) -> {
                final Set<String> matchingRoles = new HashSet<>();
                this.rolesClient.processClientRoles(client, rn, 0, Integer.MAX_VALUE, roleResult -> {
                    if (roleResult.getName().equalsIgnoreCase(rn))
                    {
                        matchingRoles.add(roleResult.getName());
                    }
                });

                String matchingRole = null;
                if (matchingRoles.size() == 1)
                {
                    matchingRole = matchingRoles.iterator().next();
                }
                else
                {
                    LOGGER.warn("Failed to match apparent Keycloak role {} from client {} to unique role via admin API", rn, client);
                }
                return matchingRole;
            };
            final Iterator<String> resourceIterator = this.resourceRoleNameMapper.keySet().iterator();
            while (!role.isPresent() && resourceIterator.hasNext())
            {
                final String resource = resourceIterator.next();
                final RoleNameMapper roleNameMapper = this.resourceRoleNameMapper.get(resource);
                role = roleNameMapper.mapAuthorityName(authorityName).map(rn -> clientRoleResolver.apply(resource, rn));
            }
        }
        return role;
    }

    /**
     *
     * {@inheritDoc}
     */
    @Override
    public Optional<String> getClientFromRole(final String authorityName)
    {
        ParameterCheck.mandatoryString("authorityName", authorityName);
        Optional<String> client = Optional.empty();
        Optional<String> role = Optional.empty();

        if (this.processRealmRoles)
        {
            role = this.realmRoleNameMapper.mapAuthorityName(authorityName);
        }
        if (!role.isPresent() && this.processResourceRoles)
        {
            final Iterator<String> resourceIterator = this.resourceRoleNameMapper.keySet().iterator();
            while (!role.isPresent() && resourceIterator.hasNext())
            {
                final String resource = resourceIterator.next();
                final RoleNameMapper roleNameMapper = this.resourceRoleNameMapper.get(resource);
                role = roleNameMapper.mapAuthorityName(authorityName);
                if (role.isPresent())
                {
                    client = Optional.of(resource);
                }
            }
        }

        return client;
    }

    protected List<Role> doFindRoles(final String shortNameFilter, final boolean realmOnly)
    {
        final List<Role> roles;

        if (this.enabled && (this.processRealmRoles || (!realmOnly && this.processResourceRoles)))
        {
            roles = new ArrayList<>();

            if (this.processRealmRoles)
            {
                LOGGER.debug("Loading roles for realm with short name filter {}", shortNameFilter);

                final Pattern shortNameFilterPattern = shortNameFilter != null && !shortNameFilter.trim().isEmpty()
                        ? this.compileShortNameFilter(shortNameFilter.trim())
                        : null;
                final List<Role> realmRoles = this.doLoadRoles(null, this.realmRoleNameFilter, this.realmRoleNameMapper,
                        shortNameFilterPattern);
                LOGGER.debug("Loaded roles {} for realm", realmRoles);
                roles.addAll(realmRoles);
            }

            if (!realmOnly && this.processResourceRoles)
            {
                this.resourceRoleNameMapper.keySet().stream().forEach(resourceName -> {
                    final List<Role> resourceRoles = this.doFindRoles(resourceName, shortNameFilter);
                    roles.addAll(resourceRoles);
                });
            }
        }
        else
        {
            if (realmOnly)
            {
                LOGGER.debug("Role mapping is not enabled either in general or for realm specifically");
            }
            else
            {
                LOGGER.debug("Role mapping is not enabled either in general, for realm or for resources specifically");
            }
            roles = Collections.emptyList();
        }

        return roles;
    }

    protected List<Role> doFindRoles(final String resourceName, final String shortNameFilter)
    {
        List<Role> roles;

        if (this.enabled && this.processResourceRoles)
        {
            final RoleNameFilter roleNameFilter = this.resourceRoleNameFilter.get(resourceName);
            final RoleNameMapper roleNameMapper = this.resourceRoleNameMapper.get(resourceName);
            if (roleNameMapper != null)
            {
                final String clientId = this.mapResourceToClientId(resourceName);
                if (clientId != null)
                {
                    LOGGER.debug("Loading roles for resource {} (client ID {}) with short name filter {}", resourceName, clientId,
                            shortNameFilter);
                    final Pattern shortNameFilterPattern = shortNameFilter != null && !shortNameFilter.trim().isEmpty()
                            ? this.compileShortNameFilter(shortNameFilter.trim())
                            : null;
                    roles = this.doLoadRoles(clientId, roleNameFilter, roleNameMapper, shortNameFilterPattern);

                    LOGGER.debug("Loaded roles {} for resource {}", roles, resourceName);
                }
                else
                {
                    LOGGER.debug("Resource name {} does not map to a client ID", resourceName);
                    roles = Collections.emptyList();
                }
            }
            else
            {
                LOGGER.debug("No role mapper defined for resource {}", resourceName);
                roles = Collections.emptyList();
            }
        }
        else
        {
            LOGGER.debug("Role mapping is not enabled either in general or for resources specifically");
            roles = Collections.emptyList();
        }

        return roles;
    }

    protected String mapResourceToClientId(final String resourceName)
    {
        LOGGER.debug("Resolving resource name {} to technical client ID", resourceName);

        String clientId;

        this.clientIdByResourceNameLock.readLock().lock();
        try
        {
            clientId = this.clientIdByResourceName.get(resourceName);
        }
        finally
        {
            this.clientIdByResourceNameLock.readLock().unlock();
        }

        if (clientId == null)
        {
            this.clientIdByResourceNameLock.writeLock().lock();
            try
            {
                clientId = this.clientIdByResourceName.get(resourceName);
                if (clientId == null)
                {
                    this.loadClientIds();

                    clientId = this.clientIdByResourceName.get(resourceName);
                    if (clientId == null)
                    {
                        this.clientIdByResourceName.put(resourceName, SENTINEL);
                    }
                }
            }
            finally
            {
                this.clientIdByResourceNameLock.writeLock().unlock();
            }
        }

        if (SENTINEL.equals(clientId))
        {
            clientId = null;
        }

        return clientId;
    }

    protected void loadClientIds()
    {
        this.clientIdByResourceNameLock.writeLock().lock();
        try
        {
            LOGGER.debug("Loading IDs for registered clients from Keycloak");
            final int processedClients = this.rolesClient.processClients(client -> {
                // Keycloak terminology is not 100% consistent
                // what the Keycloak adapter calls the resourceName is the client ID in IDM representation
                // we use clientId in our API to refer to the technical identifier which can actually be used in the ReST API to access the
                // client-specific representations
                // the IDM clientId on the other hand cannot be used anywhere in the API
                final String resourceName = client.getClientId();
                final String clientId = client.getId();

                LOGGER.trace("Loaded client {} with ID {}", resourceName, clientId);
                this.clientIdByResourceName.put(resourceName, clientId);
            });
            LOGGER.debug("Loaded / updated IDs for {} clients", processedClients);
        }
        finally
        {
            this.clientIdByResourceNameLock.writeLock().unlock();
        }
    }

    protected Pattern compileShortNameFilter(final String shortNameFilter)
    {
        ParameterCheck.mandatoryString("shortNameFilter", shortNameFilter);

        String shortNameFilterPattern = shortNameFilter;
        if (!shortNameFilterPattern.startsWith("*") && !shortNameFilterPattern.startsWith("?"))
        {
            shortNameFilterPattern = "*" + shortNameFilterPattern;
        }
        if (!shortNameFilterPattern.endsWith("*") && !shortNameFilterPattern.endsWith("?"))
        {
            shortNameFilterPattern = shortNameFilterPattern + "*";
        }

        // escape common special characters to which we don't attribute special meaning for use in regex
        shortNameFilterPattern = shortNameFilterPattern.replaceAll("([\\.(){}\\[\\]+$^])", "\\\\$1");
        // turn supported wildcards into match elements
        shortNameFilterPattern = shortNameFilterPattern.replace("*", ".*");
        shortNameFilterPattern = shortNameFilterPattern.replace("?", ".");

        final Pattern pattern = Pattern.compile(shortNameFilterPattern, Pattern.CASE_INSENSITIVE);
        LOGGER.debug("Compiled short name filter '{}' to pattern '{}'", shortNameFilter, pattern);
        return pattern;
    }

    protected List<Role> doLoadRoles(final String clientId, final RoleNameFilter filter, final RoleNameMapper mapper,
            final Pattern shortNameFilterPattern)
    {
        final List<Role> results = new ArrayList<>();

        final Consumer<RoleRepresentation> processor = r -> {
            Optional.of(r).filter(rr -> this.filterRole(rr, filter)).map(rr -> this.mapRole(rr, mapper).orElse(null))
                    .filter(role -> shortNameFilterPattern == null || this.matchRole(role, shortNameFilterPattern)).ifPresent(role -> {
                        results.add(role);
                    });
        };

        if (clientId != null)
        {
            this.rolesClient.processClientRoles(clientId, 0, Integer.MAX_VALUE, processor);
        }
        else
        {
            this.rolesClient.processRealmRoles(0, Integer.MAX_VALUE, processor);
        }

        return results;
    }

    protected boolean filterRole(final RoleRepresentation role, final RoleNameFilter filter)
    {
        LOGGER.debug("Filtering role {}", role.getName());
        final boolean exposed = filter.isRoleExposed(role.getName());
        return exposed;
    }

    protected Optional<Role> mapRole(final RoleRepresentation role, final RoleNameMapper mapper)
    {
        LOGGER.debug("Mapping role {}", role.getName());

        final Optional<String> mappedRoleName = mapper.mapRoleName(role.getName());
        final Optional<Role> mappedRole = mappedRoleName.filter(r -> {
            final boolean allowed = AuthorityType.getAuthorityType(r) == AuthorityType.ROLE;
            if (!allowed)
            {
                LOGGER.debug("Excluding role {} as it maps to group authority name {}", role.getName(), r);
            }
            return allowed;
        }).map(r -> new Role(r, role.getName(), role.getDescription()));

        mappedRole.ifPresent(r -> LOGGER.debug("Completed mapping role {}", r));

        return mappedRole;
    }

    protected boolean matchRole(final Role role, final Pattern shortNameFilterPattern)
    {
        final boolean matchResult;

        final String mappedRoleName = role.getName();
        final boolean matchesHiddenMappedRole = this.hiddenMappedRoles != null && this.hiddenMappedRoles.contains(mappedRoleName);
        if (matchesHiddenMappedRole)
        {
            LOGGER.debug("Mapped role name {} matches configured role to be hidden", mappedRoleName);
            matchResult = false;
        }
        else
        {
            final String matchRelevantMappedRoleName = mappedRoleName.substring(AuthorityType.ROLE.getPrefixString().length());
            final boolean matchesMappedName = shortNameFilterPattern.matcher(matchRelevantMappedRoleName).matches();
            final boolean matchesKeycloakName = shortNameFilterPattern.matcher(role.getKeycloakName()).matches();

            LOGGER.debug("Match result for role {} is: mapped name => {}, Keycloak name => {}", role, matchesMappedName,
                    matchesKeycloakName);
            matchResult = matchesMappedName || matchesKeycloakName;
        }

        return matchResult;
    }
}
