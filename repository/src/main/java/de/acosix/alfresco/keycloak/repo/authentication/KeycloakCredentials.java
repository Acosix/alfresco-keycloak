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
package de.acosix.alfresco.keycloak.repo.authentication;

import org.alfresco.repo.web.auth.WebCredentials;
import org.alfresco.util.ParameterCheck;
import org.keycloak.representations.AccessToken;

/**
 * @author Axel Faust
 */
public class KeycloakCredentials implements WebCredentials
{

    private static final long serialVersionUID = -4815212606223856908L;

    private final AccessToken accessToken;

    public KeycloakCredentials(final AccessToken accessToken)
    {
        ParameterCheck.mandatory("accessToken", accessToken);
        this.accessToken = accessToken;
    }

    /**
     *
     * {@inheritDoc}
     */
    @Override
    public int hashCode()
    {
        final int prime = 31;
        int result = 1;
        result = prime * result + this.accessToken.getId().hashCode();
        return result;
    }

    /**
     *
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
        if (this.getClass() != obj.getClass())
        {
            return false;
        }

        final KeycloakCredentials other = (KeycloakCredentials) obj;
        final boolean equal = this.accessToken.getId().equals(other.accessToken.getId());
        return equal;
    }
}
