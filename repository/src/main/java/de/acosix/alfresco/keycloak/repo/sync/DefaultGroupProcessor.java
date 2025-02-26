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
import org.alfresco.util.PropertyMap;
import org.keycloak.representations.idm.GroupRepresentation;

/**
 * This group synchronisation mapping processor maps the default Alfresco authority container properties from a Keycloak group.
 *
 * @author Axel Faust
 */
public class DefaultGroupProcessor implements GroupProcessor
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
        return Integer.MAX_VALUE;
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
            final PropertyMap properties = groupNode.getProperties();
            properties.put(ContentModel.PROP_AUTHORITY_NAME, group.getId());
            properties.put(ContentModel.PROP_AUTHORITY_DISPLAY_NAME, group.getName());
        }
    }

    /**
     *
     * {@inheritDoc}
     */
    @Override
    public Optional<String> mapGroupName(final GroupRepresentation group)
    {
        return this.enabled ? Optional.of(group.getId()) : Optional.empty();
    }
}
