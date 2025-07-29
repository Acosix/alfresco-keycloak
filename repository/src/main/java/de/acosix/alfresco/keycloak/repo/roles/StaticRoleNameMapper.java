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

import java.util.HashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Optional;

import org.alfresco.util.ParameterCheck;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Instances of this interface map the name of a Keycloak role using a static mapping.
 *
 * @author Axel Faust
 */
public class StaticRoleNameMapper implements RoleNameMapper
{

    private static final Logger LOGGER = LoggerFactory.getLogger(StaticRoleNameMapper.class);

    protected final Map<String, String> nameMappings = new HashMap<>();

    protected boolean upperCaseRoles;

    /**
     * @param nameMappings
     *     the nameMappings to set
     */
    public void setNameMappings(final Map<String, String> nameMappings)
    {
        this.nameMappings.clear();
        if (nameMappings != null)
        {
            this.nameMappings.putAll(nameMappings);
        }
    }

    /**
     * @param upperCaseRoles
     *     the upperCaseRoles to set
     */
    public void setUpperCaseRoles(final boolean upperCaseRoles)
    {
        this.upperCaseRoles = upperCaseRoles;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Optional<String> mapRoleName(final String roleName)
    {
        ParameterCheck.mandatoryString("roleName", roleName);

        Optional<String> result = Optional.empty();

        if (this.nameMappings != null)
        {
            final String mappedName = this.nameMappings.get(roleName);
            if (mappedName != null)
            {
                LOGGER.debug("Mapped role {} to {} using static mapping", roleName, mappedName);
                result = Optional.of(mappedName).map(name -> this.upperCaseRoles ? name.toUpperCase(Locale.ENGLISH) : name);
            }
            else
            {
                LOGGER.debug("No static mapping applies to role {}", roleName);
            }
        }

        return result;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Optional<String> mapAuthorityName(final String authorityName)
    {
        ParameterCheck.mandatoryString("authorityName", authorityName);

        Optional<String> result = Optional.empty();

        for (final Entry<String, String> entry : this.nameMappings.entrySet())
        {
            if (entry.getValue().equals(authorityName) || (this.upperCaseRoles && entry.getValue().equalsIgnoreCase(authorityName)))
            {
                final String mappedName = entry.getKey();
                LOGGER.debug("Mapped authority name {} to {} using static mapping", authorityName, mappedName);
                result = Optional.of(mappedName);
                break;
            }
        }

        if (!result.isPresent())
        {
            LOGGER.debug("No static mapping applies to authority name {}", authorityName);
        }

        return result;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public String toString()
    {
        final StringBuilder builder = new StringBuilder();
        builder.append("StaticRoleNameMapper [");
        builder.append("nameMappings=");
        builder.append(this.nameMappings);
        builder.append(", ");
        builder.append("upperCaseRoles=");
        builder.append(this.upperCaseRoles);
        builder.append("]");
        return builder.toString();
    }
}
