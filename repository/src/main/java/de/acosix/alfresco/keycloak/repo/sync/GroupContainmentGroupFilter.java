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

import java.util.Collections;

import org.keycloak.representations.idm.GroupRepresentation;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * This class provides filter capabilities for groups to be synchronised based on their parent group and whether they are contained in
 * specific groups.
 *
 * @author Axel Faust
 */
public class GroupContainmentGroupFilter extends BaseGroupContainmentFilter implements GroupFilter
{

    private static final Logger LOGGER = LoggerFactory.getLogger(GroupContainmentGroupFilter.class);

    /**
     *
     * {@inheritDoc}
     */
    @Override
    public FilterResult shouldIncludeGroup(final GroupRepresentation group)
    {
        final FilterResult res;

        if ((this.groupPaths != null && !this.groupPaths.isEmpty()) || (this.groupIds != null && !this.groupIds.isEmpty()))
        {
            LOGGER.debug(
                    "Checking group {} ({}) for containment in groups with paths {} / IDs {}, using allowTransitive={}, requireAll={}, matchDenies={}",
                    group.getId(), group.getPath(), this.groupPaths, this.groupIds, this.allowTransitive, this.requireAll,
                    this.matchDenies);

            // no need to retrieve parent group ID as path should be sufficient
            // Keycloak groups can only ever have one parent
            final String groupPath = group.getPath();
            final String parentPath = groupPath.substring(0, groupPath.lastIndexOf('/'));
            if (!parentPath.isEmpty())
            {
                final boolean parentGroupsMatch = this.parentGroupsMatch(Collections.emptyList(), Collections.singletonList(parentPath));
                if (this.matchDenies)
                {
                    res = parentGroupsMatch ? FilterResult.DENY : FilterResult.ABSTAIN;
                }
                else
                {
                    res = parentGroupsMatch ? FilterResult.ALLOW : FilterResult.ABSTAIN;
                }
            }
            else
            {
                // no parents to check
                res = FilterResult.ABSTAIN;
            }

            LOGGER.debug("Group containment result for group {}: {}", group.getId(), res);
        }
        else
        {
            res = FilterResult.ABSTAIN;
        }

        return res;
    }
}
