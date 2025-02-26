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
import java.util.Collection;
import java.util.Collections;
import java.util.Optional;

import org.alfresco.model.ContentModel;
import org.alfresco.repo.security.sync.NodeDescription;
import org.alfresco.service.namespace.QName;
import org.alfresco.util.PropertyMap;
import org.keycloak.representations.idm.UserRepresentation;

/**
 * This user synchronisation mapping processor maps the default Alfresco person properties from a Keycloak user.
 *
 * @author Axel Faust
 */
public class DefaultPersonProcessor implements UserProcessor
{

    protected boolean enabled;

    protected boolean mapNull;

    protected boolean mapFirstName;

    protected boolean mapLastName;

    protected boolean mapEmail;

    protected boolean mapEnabledState;

    /**
     * @param enabled
     *     the enabled to set
     */
    public void setEnabled(final boolean enabled)
    {
        this.enabled = enabled;
    }

    /**
     * @param mapNull
     *     the mapNull to set
     */
    public void setMapNull(final boolean mapNull)
    {
        this.mapNull = mapNull;
    }

    /**
     * @param mapFirstName
     *     the mapFirstName to set
     */
    public void setMapFirstName(final boolean mapFirstName)
    {
        this.mapFirstName = mapFirstName;
    }

    /**
     * @param mapLastName
     *     the mapLastName to set
     */
    public void setMapLastName(final boolean mapLastName)
    {
        this.mapLastName = mapLastName;
    }

    /**
     * @param mapEmail
     *     the mapEmail to set
     */
    public void setMapEmail(final boolean mapEmail)
    {
        this.mapEmail = mapEmail;
    }

    /**
     * @param mapEnabledState
     *     the mapEnabledState to set
     */
    public void setMapEnabledState(final boolean mapEnabledState)
    {
        this.mapEnabledState = mapEnabledState;
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
    public void mapUser(final UserRepresentation user, final NodeDescription person)
    {
        if (this.enabled)
        {
            final PropertyMap properties = person.getProperties();

            properties.put(ContentModel.PROP_USERNAME, user.getUsername());
            if ((this.mapNull || user.getFirstName() != null) && this.mapFirstName)
            {
                properties.put(ContentModel.PROP_FIRSTNAME, user.getFirstName());
            }
            if ((this.mapNull || user.getLastName() != null) && this.mapLastName)
            {
                properties.put(ContentModel.PROP_LASTNAME, user.getLastName());
            }
            if ((this.mapNull || user.getEmail() != null) && this.mapEmail)
            {
                properties.put(ContentModel.PROP_EMAIL, user.getEmail());
            }
            if ((this.mapNull || user.isEnabled() != null) && this.mapEnabledState)
            {
                properties.put(ContentModel.PROP_ENABLED, user.isEnabled());
            }
        }
    }

    /**
     *
     * {@inheritDoc}
     */
    @Override
    public Collection<QName> getMappedProperties()
    {
        Collection<QName> mappedProperties;
        if (this.enabled)
        {
            mappedProperties = new ArrayList<>(4);
            mappedProperties.add(ContentModel.PROP_USERNAME);
            if (this.mapFirstName)
            {
                mappedProperties.add(ContentModel.PROP_FIRSTNAME);
            }
            if (this.mapLastName)
            {
                mappedProperties.add(ContentModel.PROP_LASTNAME);
            }
            if (this.mapEmail)
            {
                mappedProperties.add(ContentModel.PROP_EMAIL);
            }
            if (this.mapEnabledState)
            {
                mappedProperties.add(ContentModel.PROP_ENABLED);
            }
        }
        else
        {
            mappedProperties = Collections.emptySet();
        }

        return mappedProperties;
    }

    /**
     *
     * {@inheritDoc}
     */
    @Override
    public Optional<String> mapUserName(final UserRepresentation user)
    {
        return this.enabled ? Optional.of(user.getUsername()) : Optional.empty();
    }
}
