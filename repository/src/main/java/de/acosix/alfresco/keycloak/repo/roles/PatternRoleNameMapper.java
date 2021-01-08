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
package de.acosix.alfresco.keycloak.repo.roles;

import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.regex.Pattern;

import org.alfresco.util.ParameterCheck;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Instances of this class map the name of a Keycloak role using regular expression patterns.
 *
 * @author Axel Faust
 */
public class PatternRoleNameMapper implements RoleNameMapper
{

    private static final Logger LOGGER = LoggerFactory.getLogger(PatternRoleNameMapper.class);

    protected Map<String, String> patternMappings;

    protected Map<String, String> patternInverseMappings;

    protected boolean upperCaseRoles;

    /**
     * @param patternMappings
     *            the patternMappings to set
     */
    public void setPatternMappings(final Map<String, String> patternMappings)
    {
        this.patternMappings = patternMappings;
    }

    /**
     * @param patternInverseMappings
     *            the patternInverseMappings to set
     */
    public void setPatternInverseMappings(final Map<String, String> patternInverseMappings)
    {
        this.patternInverseMappings = patternInverseMappings;
    }

    /**
     * @param upperCaseRoles
     *            the upperCaseRoles to set
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

        if (this.patternMappings != null)
        {
            final Optional<String> matchingPattern = this.patternMappings.keySet().stream().filter(roleName::matches).findFirst();
            result = matchingPattern.map(pattern -> {
                final String replacement = this.patternMappings.get(pattern);
                LOGGER.debug("Role {} matches mapping pattern {} - applying replacement pattern {}", roleName, pattern, replacement);
                final String mappedName = roleName.replaceAll(pattern, replacement);
                LOGGER.debug("Mapped role {} to {}", roleName, mappedName);
                return mappedName;
            }).map(name -> this.upperCaseRoles ? name.toUpperCase(Locale.ENGLISH) : name);

            if (!result.isPresent())
            {
                LOGGER.debug("No matching pattern applies to role {}", roleName);
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

        if (this.patternInverseMappings != null)
        {
            final Optional<String> matchingPattern = this.patternMappings.keySet().stream().filter(pattern -> Pattern
                    .compile(pattern, this.upperCaseRoles ? Pattern.CASE_INSENSITIVE : 0).matcher(authorityName).matches()).findFirst();

            result = matchingPattern.map(pattern -> {
                final String replacement = this.patternMappings.get(pattern);
                LOGGER.debug("Authority name {} matches inverse mapping pattern {} - applying replacement pattern {}", authorityName,
                        pattern, replacement);
                final String mappedName = Pattern.compile(pattern, this.upperCaseRoles ? Pattern.CASE_INSENSITIVE : 0)
                        .matcher(authorityName).replaceAll(replacement);
                LOGGER.debug("Mapped authority name {} to {}", authorityName, mappedName);
                return mappedName;
            }).map(name -> this.upperCaseRoles ? name.toLowerCase(Locale.ENGLISH) : name);
        }

        return result;
    }
}
