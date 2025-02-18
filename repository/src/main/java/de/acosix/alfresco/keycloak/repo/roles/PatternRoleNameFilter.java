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

import org.alfresco.util.ParameterCheck;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Instances of this class test the name of a Keycloak role using regular expression patterns.
 *
 * @author Axel Faust
 */
public class PatternRoleNameFilter implements RoleNameFilter
{

    private static final Logger LOGGER = LoggerFactory.getLogger(PatternRoleNameFilter.class);

    protected List<String> allowedRoleNamePatterns;

    protected List<String> forbiddenRoleNamePatterns;

    /**
     * @param allowedRoleNamePatterns
     *            the allowedRoleNamePatterns to set
     */
    public void setAllowedRoleNamePatterns(final List<String> allowedRoleNamePatterns)
    {
        this.allowedRoleNamePatterns = allowedRoleNamePatterns;
    }

    /**
     * @param forbiddenRoleNamePatterns
     *            the forbiddenRoleNamePatterns to set
     */
    public void setForbiddenRoleNamePatterns(final List<String> forbiddenRoleNamePatterns)
    {
        this.forbiddenRoleNamePatterns = forbiddenRoleNamePatterns;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public boolean isRoleExposed(final String roleName)
    {
        ParameterCheck.mandatoryString("roleName", roleName);

        boolean exposed;

        final boolean matchAllowedPattern = this.allowedRoleNamePatterns != null
                ? this.allowedRoleNamePatterns.stream().anyMatch(roleName::matches)
                : true;
        final boolean notMatchForbiddenPattern = this.forbiddenRoleNamePatterns != null
                ? !this.forbiddenRoleNamePatterns.stream().anyMatch(roleName::matches)
                : true;

        exposed = matchAllowedPattern && notMatchForbiddenPattern;
        LOGGER.debug("Determined exposure flag of {} for role {} using a static match pattern set", exposed, roleName);

        return exposed;
    }

}
