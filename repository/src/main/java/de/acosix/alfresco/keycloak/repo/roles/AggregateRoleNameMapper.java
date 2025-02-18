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

import java.util.List;
import java.util.Locale;
import java.util.Optional;

import org.alfresco.util.ParameterCheck;
import org.alfresco.util.PropertyCheck;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.InitializingBean;

/**
 * Instances of this class map the name of a Keycloak role using a prioritised list of mappers from which the first non-{@code null} mapping
 * result is used as the overall mapping result.
 *
 * @author Axel Faust
 */
public class AggregateRoleNameMapper implements InitializingBean, RoleNameMapper
{

    private static final Logger LOGGER = LoggerFactory.getLogger(AggregateRoleNameMapper.class);

    protected List<RoleNameMapper> granularMappers;

    protected boolean upperCaseRoles;

    /**
     *
     * {@inheritDoc}
     */
    @Override
    public void afterPropertiesSet()
    {
        PropertyCheck.mandatory(this, "granularMappers", this.granularMappers);
    }

    /**
     * @param granularMappers
     *     the granularMappers to set
     */
    public void setGranularMappers(final List<RoleNameMapper> granularMappers)
    {
        this.granularMappers = granularMappers;
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
        LOGGER.debug("Mapping role {} using granular mappers {}", roleName, this.granularMappers);
        Optional<String> mappedName = Optional.empty();
        for (final RoleNameMapper mapper : this.granularMappers)
        {
            mappedName = mapper.mapRoleName(roleName).map(name -> this.upperCaseRoles ? name.toUpperCase(Locale.ENGLISH) : name);
            if (mappedName.isPresent())
            {
                LOGGER.debug("Mapped role {} to {} using granular mapper {}", roleName, mappedName, mapper);
                break;
            }
        }
        return mappedName;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Optional<String> mapAuthorityName(final String authorityName)
    {
        ParameterCheck.mandatoryString("authorityName", authorityName);
        LOGGER.debug("Mapping authority name {} using granular mappers {}", authorityName, this.granularMappers);
        Optional<String> mappedName = Optional.empty();
        for (final RoleNameMapper mapper : this.granularMappers)
        {
            mappedName = mapper.mapAuthorityName(authorityName).map(name -> this.upperCaseRoles ? name.toLowerCase(Locale.ENGLISH) : name);
            if (mappedName.isPresent())
            {
                LOGGER.debug("Mapped authority name {} to {} using granular mapper {}", authorityName, mappedName, mapper);
                break;
            }
        }
        return mappedName;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public String toString()
    {
        final StringBuilder builder = new StringBuilder();
        builder.append("AggregateRoleNameMapper [");
        if (this.granularMappers != null)
        {
            builder.append("granularMappers=");
            builder.append(this.granularMappers);
            builder.append(", ");
        }
        builder.append("upperCaseRoles=");
        builder.append(this.upperCaseRoles);
        builder.append("]");
        return builder.toString();
    }

}
