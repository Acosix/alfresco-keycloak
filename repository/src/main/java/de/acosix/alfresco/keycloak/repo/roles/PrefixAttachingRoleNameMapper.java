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

import java.util.Locale;
import java.util.Optional;

import org.alfresco.util.ParameterCheck;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Instances of this class map the name of a Keycloak role by simply attaching a static prefix to all role names in order to avoid
 * overlaps with similarly named roles, e.g. from other clients / realms.
 *
 * @author Axel Faust
 */
public class PrefixAttachingRoleNameMapper implements RoleNameMapper
{

    private static final Logger LOGGER = LoggerFactory.getLogger(PrefixAttachingRoleNameMapper.class);

    protected String prefix;

    protected boolean upperCaseRoles;

    /**
     * @param prefix
     *     the prefix to set
     */
    public void setPrefix(final String prefix)
    {
        this.prefix = prefix;
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

        if (this.prefix != null)
        {
            final String mappedName = this.prefix + roleName;
            LOGGER.debug("Mapped role {} to {} using prefix attachment", roleName, mappedName);
            result = Optional.of(mappedName).map(name -> this.upperCaseRoles ? name.toUpperCase(Locale.ENGLISH) : name);
        }

        return result;
    }

    @Override
    public Optional<String> mapAuthorityName(final String authorityName)
    {
        ParameterCheck.mandatoryString("authorityName", authorityName);

        Optional<String> result = Optional.empty();

        if (this.prefix != null)
        {
            final String ciAuthorityName = authorityName.toLowerCase(Locale.ENGLISH);
            final String ciPrefix = this.prefix.toLowerCase(Locale.ENGLISH);
            if (ciAuthorityName.startsWith(ciPrefix))
            {
                final String mappedName = authorityName.substring(this.prefix.length());
                LOGGER.debug("Mapped authority name {} to {} using prefix removal", authorityName, mappedName);
                result = Optional.of(mappedName);
            }
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
        builder.append("PrefixAttachingRoleNameMapper [");
        if (this.prefix != null)
        {
            builder.append("prefix=");
            builder.append(this.prefix);
            builder.append(", ");
        }
        builder.append("upperCaseRoles=");
        builder.append(this.upperCaseRoles);
        builder.append("]");
        return builder.toString();
    }

}
