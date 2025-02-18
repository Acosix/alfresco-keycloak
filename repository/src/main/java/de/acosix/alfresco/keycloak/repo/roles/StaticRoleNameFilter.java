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

import java.util.HashSet;
import java.util.Set;

import org.alfresco.util.ParameterCheck;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Instances of this class test the name of a Keycloak role using a static match set.
 *
 * @author Axel Faust
 */
public class StaticRoleNameFilter implements RoleNameFilter
{

    private static final Logger LOGGER = LoggerFactory.getLogger(StaticRoleNameFilter.class);

    protected final Set<String> allowedRoles = new HashSet<>();

    /**
     * @param allowedRoles
     *     the allowedRoles to set
     */
    public void setAllowedRoles(final Set<String> allowedRoles)
    {
        this.allowedRoles.clear();
        if (allowedRoles != null)
        {
            this.allowedRoles.addAll(allowedRoles);
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public boolean isRoleExposed(final String roleName)
    {
        ParameterCheck.mandatoryString("roleName", roleName);

        final boolean exposed = this.allowedRoles.contains(roleName);
        LOGGER.debug("Determined exposure flag of {} for role {} using a static match set", exposed, roleName);

        return exposed;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public String toString()
    {
        final StringBuilder builder = new StringBuilder();
        builder.append("StaticRoleNameFilter [");
        builder.append("allowedRoles=");
        builder.append(this.allowedRoles);
        builder.append("]");
        return builder.toString();
    }

}
