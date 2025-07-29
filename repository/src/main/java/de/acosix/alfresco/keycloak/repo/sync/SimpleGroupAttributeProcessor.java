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

import java.util.Optional;

import org.alfresco.model.ContentModel;
import org.alfresco.repo.security.sync.NodeDescription;
import org.keycloak.representations.idm.GroupRepresentation;

/**
 * Instances of this class perform simple mappings from Keycloak group attributes to authority container node description properties.
 *
 * @author Axel Faust
 */
public class SimpleGroupAttributeProcessor extends BaseAttributeProcessor implements GroupProcessor
{

    protected boolean enabled;

    /**
     * @param enabled
     *     the enabled to set
     */
    public void setEnabled(final boolean enabled)
    {
        this.enabled = enabled;
    }

    /**
     *
     * {@inheritDoc}
     */
    @Override
    public int getPriority()
    {
        return this.priority;
    }

    /**
     *
     * {@inheritDoc}
     */
    @Override
    public void mapGroup(final GroupRepresentation group, final NodeDescription groupNode)
    {
        if (this.enabled)
        {
            this.map(group.getAttributes(), groupNode);
        }
    }

    /**
     *
     * {@inheritDoc}
     */
    @Override
    public Optional<String> mapGroupName(final GroupRepresentation group)
    {
        return this.enabled ? this.mapAuthorityName(ContentModel.PROP_AUTHORITY_NAME, group.getAttributes()) : Optional.empty();
    }
}
