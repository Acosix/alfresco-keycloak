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
package de.acosix.alfresco.keycloak.repo.sync;

import java.util.Arrays;
import java.util.List;

import org.keycloak.representations.idm.GroupRepresentation;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * This class provides filter capabilities for groups to be synchronised based on their parent group and whether they are contained in
 * specific groups.
 *
 * @author Axel Faust
 */
public class GroupPathFilter implements GroupFilter
{

    private static final Logger LOGGER = LoggerFactory.getLogger(GroupPathFilter.class);

    protected List<String> groupPaths;

    protected boolean matchDenies;

    /**
     * @param groupPaths
     *     the groupPaths to set as a comma-separated string of paths
     */
    public void setGroupPaths(final String groupPaths)
    {
        this.groupPaths = groupPaths != null && !groupPaths.isEmpty() ? Arrays.asList(groupPaths.split(",")) : null;
    }

    /**
     * @param matchDenies
     *     the matchDenies to set
     */
    public void setMatchDenies(final boolean matchDenies)
    {
        this.matchDenies = matchDenies;
    }

    /**
     *
     * {@inheritDoc}
     */
    @Override
    public FilterResult shouldIncludeGroup(final GroupRepresentation group)
    {
        final FilterResult res;

        if ((this.groupPaths != null && !this.groupPaths.isEmpty()))
        {
            LOGGER.debug("Checking group {} ({}) against paths {}, using matchDenies={}", group.getId(), group.getPath(), this.groupPaths,
                    this.matchDenies);

            final String groupPath = group.getPath();
            final boolean containsGroup = this.groupPaths.contains(groupPath);
            if (this.matchDenies)
            {
                res = containsGroup ? FilterResult.DENY : FilterResult.ABSTAIN;
            }
            else
            {
                res = containsGroup ? FilterResult.ALLOW : FilterResult.ABSTAIN;
            }

            LOGGER.debug("Group path check result for group {}: {}", group.getId(), res);
        }
        else
        {
            res = FilterResult.ABSTAIN;
        }

        return res;
    }
}
