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

import java.util.Set;

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

    protected Set<String> allowedRoleNamePatterns;

    /**
     * @param allowedRoleNamePatterns
     *            the allowedRoleNamePatterns to set
     */
    public void setAllowedRoleNamePatterns(final Set<String> allowedRoleNamePatterns)
    {
        this.allowedRoleNamePatterns = allowedRoleNamePatterns;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public boolean isRoleExposed(final String roleName)
    {
        ParameterCheck.mandatoryString("roleName", roleName);

        boolean exposed = false;

        if (this.allowedRoleNamePatterns != null)
        {
            exposed = this.allowedRoleNamePatterns.stream().anyMatch(roleName::matches);
            LOGGER.debug("Determined exposure flag of {} for role {} using a static match pattern set", exposed, roleName);
        }

        return exposed;
    }

}
