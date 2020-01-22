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
package de.acosix.alfresco.keycloak.repo.sync;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import de.acosix.alfresco.keycloak.repo.deps.keycloak.representations.idm.GroupRepresentation;

/**
 * This class provides filter capabilities for groups to be synchronised based on their parent group and whether they are contained in
 * specific groups.
 *
 * @author Axel Faust
 */
public class GroupContainmentGroupFilter extends BaseGroupContainmentFilter
        implements GroupFilter
{

    private static final Logger LOGGER = LoggerFactory.getLogger(GroupContainmentGroupFilter.class);

    /**
     *
     * {@inheritDoc}
     */
    @Override
    public boolean shouldIncludeGroup(final GroupRepresentation group)
    {
        boolean matches;

        if ((this.groupPaths != null && !this.groupPaths.isEmpty()) || (this.groupIds != null && !this.groupIds.isEmpty()))
        {
            LOGGER.debug(
                    "Checking group {} ({}) for containment in groups with paths {} / IDs {}, using allowTransitive={} and requireAll={}",
                    group.getId(), group.getPath(), this.groupPaths, this.groupIds, this.allowTransitive, this.requireAll);

            // no need to retrieve parent group ID as path should be sufficient
            // Keycloak groups can only ever have one parent

            final List<String> parentGroupIds = Collections.emptyList();
            final List<String> parentGroupPaths = new ArrayList<>();

            final String groupPath = group.getPath();
            final String parentPath = groupPath.substring(0, groupPath.lastIndexOf('/'));
            if (!parentPath.isEmpty())
            {
                parentGroupPaths.add(parentPath);
            }

            matches = this.parentGroupsMatch(parentGroupIds, parentGroupPaths);

            LOGGER.debug("Group containment result for group {}: {}", group.getId(), matches);
        }
        else
        {
            matches = true;
        }

        return matches;
    }
}
