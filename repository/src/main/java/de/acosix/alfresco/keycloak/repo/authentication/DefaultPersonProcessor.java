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

import java.io.Serializable;
import java.util.Map;

import org.alfresco.model.ContentModel;
import org.alfresco.service.namespace.NamespaceService;
import org.alfresco.service.namespace.QName;
import org.keycloak.representations.AccessToken;
import org.keycloak.representations.IDToken;

/**
 * This user authentication mapping processor maps the default Alfresco person properties from an authenticated Keycloak user.
 *
 * @author Axel Faust
 */
public class DefaultPersonProcessor implements UserProcessor
{

    // missing in ContentModel constants
    private static final QName PROP_MIDDLE_NAME = QName.createQName(NamespaceService.CONTENT_MODEL_1_0_URI, "middleName");

    protected boolean enabled;

    protected boolean mapNull;

    protected boolean mapGivenName;

    protected boolean mapMiddleName;

    protected boolean mapFamilyName;

    protected boolean mapEmail;

    protected boolean mapPhoneNumber;

    protected boolean mapPhoneNumberAsMobile;

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
     * @param mapGivenName
     *     the mapGivenName to set
     */
    public void setMapGivenName(final boolean mapGivenName)
    {
        this.mapGivenName = mapGivenName;
    }

    /**
     * @param mapMiddleName
     *     the mapMiddleName to set
     */
    public void setMapMiddleName(final boolean mapMiddleName)
    {
        this.mapMiddleName = mapMiddleName;
    }

    /**
     * @param mapFamilyName
     *     the mapFamilyName to set
     */
    public void setMapFamilyName(final boolean mapFamilyName)
    {
        this.mapFamilyName = mapFamilyName;
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
     * @param mapPhoneNumber
     *     the mapPhoneNumber to set
     */
    public void setMapPhoneNumber(final boolean mapPhoneNumber)
    {
        this.mapPhoneNumber = mapPhoneNumber;
    }

    /**
     * @param mapPhoneNumberAsMobile
     *     the mapPhoneNumberAsMobile to set
     */
    public void setMapPhoneNumberAsMobile(final boolean mapPhoneNumberAsMobile)
    {
        this.mapPhoneNumberAsMobile = mapPhoneNumberAsMobile;
    }

    /**
     *
     * {@inheritDoc}
     */
    @Override
    public void mapUser(final AccessToken accessToken, final IDToken idToken, final Map<QName, Serializable> personNodeProperties)
    {
        if (this.enabled && idToken != null)
        {
            if ((this.mapNull || idToken.getGivenName() != null) && this.mapGivenName)
            {
                personNodeProperties.put(ContentModel.PROP_FIRSTNAME, idToken.getGivenName());
            }
            if ((this.mapNull || idToken.getMiddleName() != null) && this.mapMiddleName)
            {
                personNodeProperties.put(PROP_MIDDLE_NAME, idToken.getMiddleName());
            }
            if ((this.mapNull || idToken.getFamilyName() != null) && this.mapFamilyName)
            {
                personNodeProperties.put(ContentModel.PROP_LASTNAME, idToken.getFamilyName());
            }
            if ((this.mapNull || idToken.getEmail() != null) && this.mapEmail)
            {
                personNodeProperties.put(ContentModel.PROP_EMAIL, idToken.getEmail());
            }
            if ((this.mapNull || idToken.getPhoneNumber() != null) && this.mapPhoneNumber)
            {
                personNodeProperties.put(this.mapPhoneNumberAsMobile ? ContentModel.PROP_MOBILE : ContentModel.PROP_TELEPHONE,
                        idToken.getPhoneNumber());
            }
        }
    }
}
