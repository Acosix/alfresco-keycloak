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
import java.util.Arrays;
import java.util.Collection;
import java.util.List;

import org.alfresco.util.ParameterCheck;
import org.alfresco.util.PropertyCheck;
import org.springframework.beans.factory.InitializingBean;

import de.acosix.alfresco.keycloak.repo.client.IdentitiesClient;

/**
 * This class provides common configuration and logic relevant for any filter based on authority group containments.
 *
 * @author Axel Faust
 */
public abstract class BaseGroupContainmentFilter implements InitializingBean
{

    protected IdentitiesClient identitiesClient;

    protected List<String> groupPaths;

    protected List<String> groupIds;

    protected List<String> idResolvedGroupPaths;

    protected boolean matchDenies;

    protected boolean requireAll = false;

    protected boolean allowTransitive = true;

    protected int groupLoadBatchSize = 50;

    /**
     *
     * {@inheritDoc}
     */
    @Override
    public void afterPropertiesSet()
    {
        PropertyCheck.mandatory(this, "identitiesClient", this.identitiesClient);

        if (this.groupIds != null && !this.groupIds.isEmpty())
        {
            this.idResolvedGroupPaths = new ArrayList<>();
            this.groupIds.stream().map(id -> this.identitiesClient.getGroup(id).getPath()).forEach(this.idResolvedGroupPaths::add);
        }
    }

    /**
     * @param identitiesClient
     *     the identitiesClient to set
     */
    public void setIdentitiesClient(final IdentitiesClient identitiesClient)
    {
        this.identitiesClient = identitiesClient;
    }

    /**
     * @param groupPaths
     *     the groupPaths to set as a comma-separated string of paths
     */
    public void setGroupPaths(final String groupPaths)
    {
        this.groupPaths = groupPaths != null && !groupPaths.isEmpty() ? Arrays.asList(groupPaths.split(",")) : null;
    }

    /**
     * @param groupIds
     *     the groupIds to set as a comma-separated string of paths
     */
    public void setGroupIds(final String groupIds)
    {
        this.groupIds = groupIds != null && !groupIds.isEmpty() ? Arrays.asList(groupIds.split(",")) : null;
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
     * @param requireAll
     *     the requireAll to set
     */
    public void setRequireAll(final boolean requireAll)
    {
        this.requireAll = requireAll;
    }

    /**
     * @param allowTransitive
     *     the allowTransitive to set
     */
    public void setAllowTransitive(final boolean allowTransitive)
    {
        this.allowTransitive = allowTransitive;
    }

    /**
     * @param groupLoadBatchSize
     *     the groupLoadBatchSize to set
     */
    public void setGroupLoadBatchSize(final int groupLoadBatchSize)
    {
        this.groupLoadBatchSize = groupLoadBatchSize;
    }

    /**
     * Checks whether parent groups match the configured restrictions.
     *
     * @param parentGroupIds
     *     the list of parent group IDs for an authority
     * @param parentGroupPaths
     *     the list of parent group paths for an authority
     * @return {@code true} if the parent groups match the configured restrictions, {@code false} otherwise
     */
    protected boolean parentGroupsMatch(final List<String> parentGroupIds, final List<String> parentGroupPaths)
    {
        ParameterCheck.mandatory("parentGroupIds", parentGroupIds);
        ParameterCheck.mandatory("parentGroupPaths", parentGroupPaths);

        boolean matches;

        if (this.requireAll)
        {
            if (this.allowTransitive)
            {
                final boolean allPathsMatch = this.groupPaths == null
                        || this.groupPaths.stream().allMatch(path -> this.groupPathOrTransitiveContained(path, parentGroupPaths));
                final boolean allResolvedPathsMatch = this.idResolvedGroupPaths == null
                        || this.idResolvedGroupPaths.stream().allMatch(path -> this.groupPathOrTransitiveContained(path, parentGroupPaths));
                matches = allPathsMatch && allResolvedPathsMatch;
            }
            else
            {
                final boolean allPathsMatch = this.groupPaths == null || this.groupPaths.stream().allMatch(parentGroupPaths::contains);
                // parentGroupIds might be empty if they cannot be efficiently retrieved or paths are sufficiently known
                final boolean allIdsMatch = this.groupIds == null || this.groupIds.stream().allMatch(parentGroupIds::contains)
                        || this.idResolvedGroupPaths.stream().allMatch(parentGroupPaths::contains);
                matches = allPathsMatch && allIdsMatch;
            }
        }
        else
        {
            if (this.allowTransitive)
            {
                matches = (this.groupPaths != null
                        && this.groupPaths.stream().anyMatch(path -> this.groupPathOrTransitiveContained(path, parentGroupPaths)));
                matches = matches || (this.idResolvedGroupPaths != null && this.idResolvedGroupPaths.stream()
                        .anyMatch(path -> this.groupPathOrTransitiveContained(path, parentGroupPaths)));
            }
            else
            {
                matches = (this.groupPaths != null && this.groupPaths.stream().anyMatch(parentGroupPaths::contains));
                matches = matches || (this.groupIds != null && (this.groupIds.stream().anyMatch(parentGroupIds::contains)
                        || this.idResolvedGroupPaths.stream().anyMatch(parentGroupPaths::contains)));
            }
        }

        return matches;
    }

    /**
     * Checks whether a specific group path matches any entry in a list of paths using either exact match or prefix matching.
     *
     * @param groupPath
     *     the path to check
     * @param groupPaths
     *     the paths to check against
     * @return {@code true} if the path matches one of the paths in exact match or prefix matching mode
     */
    protected boolean groupPathOrTransitiveContained(final String groupPath, final Collection<String> groupPaths)
    {
        boolean contained = groupPaths.contains(groupPath);
        final String groupPathPrefix = groupPath + "/";
        contained = contained || groupPaths.stream().anyMatch(path -> path.startsWith(groupPathPrefix));
        return contained;
    }
}
