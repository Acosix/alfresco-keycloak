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

import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.Optional;

import org.alfresco.model.ContentModel;
import org.alfresco.repo.security.sync.NodeDescription;
import org.alfresco.service.namespace.QName;
import org.keycloak.representations.idm.UserRepresentation;

/**
 * Instances of this class perform simple mappings from Keycloak user attributes to person node description properties.
 *
 * @author Axel Faust
 */
public class SimpleUserAttributeProcessor extends BaseAttributeProcessor implements UserProcessor
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
    public void mapUser(final UserRepresentation user, final NodeDescription person)
    {
        if (this.enabled)
        {
            this.map(user.getAttributes(), person);
        }
    }

    /**
     *
     * {@inheritDoc}
     */
    @Override
    public Collection<QName> getMappedProperties()
    {
        return this.enabled ? new HashSet<>(this.attributePropertyQNameMappings.values()) : Collections.emptySet();
    }

    /**
     *
     * {@inheritDoc}
     */
    @Override
    public Optional<String> mapUserName(final UserRepresentation user)
    {
        return this.enabled ? this.mapAuthorityName(ContentModel.PROP_USERNAME, user.getAttributes()) : Optional.empty();
    }

}
