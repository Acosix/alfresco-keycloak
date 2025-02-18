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

import org.alfresco.service.cmr.security.AuthorityType;
import org.alfresco.util.ParameterCheck;

/**
 * Instances of this class represent a Keycloak role mapped to an Alfresco {@link AuthorityType#ROLE ROLE} authority on-the-fly.
 *
 * @author Axel Faust
 */
public class Role
{

    private final String name;

    private final String keycloakName;

    private final String description;

    /**
     * Constructs a new instance of this class.
     *
     * @param name
     *            the name of the Alfresco authority
     * @param keycloakName
     *            the name of the Keycloak role
     * @param description
     *            the description of the Keycloak role
     */
    public Role(final String name, final String keycloakName, final String description)
    {
        ParameterCheck.mandatoryString("name", name);
        ParameterCheck.mandatoryString("keycloakName", keycloakName);

        this.name = name;
        this.keycloakName = keycloakName;
        this.description = description;
    }

    /**
     * @return the name
     */
    public String getName()
    {
        return this.name;
    }

    /**
     * @return the keycloakName
     */
    public String getKeycloakName()
    {
        return this.keycloakName;
    }

    /**
     * @return the description
     */
    public String getDescription()
    {
        return this.description;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public int hashCode()
    {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((this.name == null) ? 0 : this.name.hashCode());
        result = prime * result + ((this.keycloakName == null) ? 0 : this.keycloakName.hashCode());
        result = prime * result + ((this.description == null) ? 0 : this.description.hashCode());
        return result;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public boolean equals(final Object obj)
    {
        if (this == obj)
        {
            return true;
        }
        if (obj == null)
        {
            return false;
        }
        if (!(obj instanceof Role))
        {
            return false;
        }
        final Role other = (Role) obj;
        if (this.name == null)
        {
            if (other.name != null)
            {
                return false;
            }
        }
        else if (!this.name.equals(other.name))
        {
            return false;
        }
        if (this.keycloakName == null)
        {
            if (other.keycloakName != null)
            {
                return false;
            }
        }
        else if (!this.keycloakName.equals(other.keycloakName))
        {
            return false;
        }
        if (this.description == null)
        {
            if (other.description != null)
            {
                return false;
            }
        }
        else if (!this.description.equals(other.description))
        {
            return false;
        }
        return true;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public String toString()
    {
        final StringBuilder builder = new StringBuilder();
        builder.append("Role [");
        if (this.name != null)
        {
            builder.append("name=");
            builder.append(this.name);
            builder.append(", ");
        }
        if (this.keycloakName != null)
        {
            builder.append("keycloakName=");
            builder.append(this.keycloakName);
        }
        if (this.description != null)
        {
            builder.append("description=");
            builder.append(this.description);
        }
        builder.append("]");
        return builder.toString();
    }

}
