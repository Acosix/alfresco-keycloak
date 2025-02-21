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

import java.util.ArrayList;
import java.util.List;

import org.keycloak.representations.idm.UserRepresentation;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.InitializingBean;

/**
 * This class provides filter capabilities for users to be synchronised based on the groups they are a member of and whether they are
 * contained in specific groups.
 *
 * @author Axel Faust
 */
public class GroupContainmentUserFilter extends BaseGroupContainmentFilter implements UserFilter, InitializingBean
{

    private static final Logger LOGGER = LoggerFactory.getLogger(GroupContainmentUserFilter.class);

    /**
     *
     * {@inheritDoc}
     */
    @Override
    public FilterResult shouldIncludeUser(final UserRepresentation user)
    {
        final FilterResult res;

        if ((this.groupPaths != null && !this.groupPaths.isEmpty()) || (this.groupIds != null && !this.groupIds.isEmpty()))
        {
            LOGGER.debug(
                    "Checking user {} for containment in groups with paths {} / IDs {}, using allowTransitive={}, requireAll={}, matchDenies={}",
                    user.getUsername(), this.groupPaths, this.groupIds, this.allowTransitive, this.requireAll, this.matchDenies);

            final List<String> parentGroupIds = new ArrayList<>();
            final List<String> parentGroupPaths = new ArrayList<>();

            int offset = 0;
            int processedGroups = 1;
            while (processedGroups > 0)
            {
                processedGroups = this.identitiesClient.processUserGroups(user.getId(), offset, this.groupLoadBatchSize, group -> {
                    parentGroupIds.add(group.getId());
                    parentGroupPaths.add(group.getPath());
                });
                offset += processedGroups;
            }

            if (parentGroupIds.isEmpty() || parentGroupPaths.isEmpty())
            {
                final boolean parentGroupsMatch = this.parentGroupsMatch(parentGroupIds, parentGroupPaths);
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

            LOGGER.debug("Group containment result for user {}: {}", user.getUsername(), res);
        }
        else
        {
            res = FilterResult.ABSTAIN;
        }

        return res;
    }
}
