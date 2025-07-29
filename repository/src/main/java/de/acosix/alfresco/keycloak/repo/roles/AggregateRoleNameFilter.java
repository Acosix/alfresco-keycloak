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

import org.alfresco.util.PropertyCheck;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.InitializingBean;

/**
 * Instances of this class test the name of a Keycloak role using a prioritised list of granular filters from which a single affirmative
 * test result is required to provide an overall affirmative test result.
 *
 * @author Axel Faust
 */
public class AggregateRoleNameFilter implements InitializingBean, RoleNameFilter
{

    private static final Logger LOGGER = LoggerFactory.getLogger(AggregateRoleNameFilter.class);

    protected List<RoleNameFilter> granularFilters;

    /**
     *
     * {@inheritDoc}
     */
    @Override
    public void afterPropertiesSet()
    {
        PropertyCheck.mandatory(this, "granularFilters", this.granularFilters);
    }

    /**
     * @param granularFilters
     *            the granularFilters to set
     */
    public void setGranularFilters(final List<RoleNameFilter> granularFilters)
    {
        this.granularFilters = granularFilters;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public boolean isRoleExposed(final String roleName)
    {
        LOGGER.debug("Testing role {} for exposure using granular filters {}", roleName, this.granularFilters);
        final boolean exposed = this.granularFilters.isEmpty() || this.granularFilters.stream().anyMatch(f -> f.isRoleExposed(roleName));
        LOGGER.debug("Determined exposure flag of {} for role {} using a granular filter list", exposed, roleName);
        return exposed;
    }

}
