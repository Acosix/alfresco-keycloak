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
package de.acosix.alfresco.keycloak.repo.util;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * This class bundles static utility operations meant to bridge slightly different APIs of Alfresco versions, so that the Keycloak module
 * can run on
 * in as many Alfresco versions as possible.
 *
 * @author Axel Faust
 */
public class AlfrescoCompatibilityUtil
{

    private static final Logger LOGGER = LoggerFactory.getLogger(AlfrescoCompatibilityUtil.class);

    /**
     * Masks the user name except for the first two characters. This method has been ported from 6.1+ Alfresco AuthenticationUtil for use in
     * any Alfresco version.
     *
     * @param userName
     *            the user name to mask
     * @return the masked user name
     */
    public static String maskUsername(final String userName)
    {
        if (userName != null)
        {
            try
            {
                if (userName.length() >= 2)
                {
                    return userName.substring(0, 2) + new String(new char[(userName.length() - 2)]).replace("\0", "*");
                }
            }
            catch (final Exception e)
            {
                LOGGER.debug("Failed to mask the username", e);
            }
            return userName;
        }
        return null;
    }
}
