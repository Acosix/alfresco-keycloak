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
package de.acosix.alfresco.keycloak.share.web;

import java.util.HashMap;
import java.util.Map;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletRequestWrapper;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;

import org.alfresco.util.PropertyCheck;
import org.alfresco.web.site.servlet.SlingshotLoginController;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.extensions.surf.UserFactory;
import org.springframework.extensions.surf.exception.ConnectorServiceException;
import org.springframework.extensions.surf.support.AlfrescoUserFactory;
import org.springframework.extensions.webscripts.Status;
import org.springframework.extensions.webscripts.connector.Connector;
import org.springframework.extensions.webscripts.connector.ConnectorContext;
import org.springframework.extensions.webscripts.connector.ConnectorService;
import org.springframework.extensions.webscripts.connector.CredentialVault;
import org.springframework.extensions.webscripts.connector.Credentials;
import org.springframework.extensions.webscripts.connector.HttpMethod;
import org.springframework.extensions.webscripts.connector.Response;

/**
 * This specialised variant of a login controller performs user name corrections upon successful authantication of a user, in case the
 * Repository tier authentication has resulted in any deviation from the user-provided user name. This may be the case because of case
 * matching or alternative login attributes (like email) being supported that resolve back to a preferred user name.
 *
 * @author Axel Faust
 */
public class UserNameCorrectingSlingshotLoginController extends SlingshotLoginController implements InitializingBean
{

    private static final Logger LOGGER = LoggerFactory.getLogger(UserNameCorrectingSlingshotLoginController.class);

    protected ConnectorService connectorService;

    /**
     *
     * {@inheritDoc}
     */
    @Override
    public void afterPropertiesSet()
    {
        PropertyCheck.mandatory(this, "connectorService", this.connectorService);
    }

    /**
     * @param connectorService
     *            the connectorService to set
     */
    public void setConnectorService(final ConnectorService connectorService)
    {
        this.connectorService = connectorService;
    }

    /**
     *
     * {@inheritDoc}
     */
    @Override
    protected void onSuccess(final HttpServletRequest request, final HttpServletResponse response) throws Exception
    {
        final HttpSession session = request.getSession();
        String userName = request.getParameter(PARAM_USERNAME);
        if (userName == null)
        {
            userName = (String) session.getAttribute(UserFactory.SESSION_ATTRIBUTE_KEY_USER_ID);
        }

        final String effectiveUserName = this.loadEffectiveUserName(request, session, userName);

        HttpServletRequest effectiveRequest = request;
        if (effectiveUserName != null && !effectiveUserName.equals(userName))
        {
            // store the proper user ID in session and facade the servlet request for the remainder of the operation to expose only the
            // effective user name
            session.setAttribute(UserFactory.SESSION_ATTRIBUTE_KEY_USER_ID, effectiveUserName);
            effectiveRequest = new HttpServletRequestWrapper(request)
            {

                /**
                 *
                 * {@inheritDoc}
                 */
                @Override
                public String getParameter(final String name)
                {
                    if (PARAM_USERNAME.equals(name))
                    {
                        return effectiveUserName;
                    }
                    return super.getParameter(name);
                }

                /**
                 *
                 * {@inheritDoc}
                 */
                @Override
                public String[] getParameterValues(final String name)
                {
                    if (PARAM_USERNAME.equals(name))
                    {
                        return new String[] { effectiveUserName };
                    }
                    return super.getParameterValues(name);
                }

                /**
                 *
                 * {@inheritDoc}
                 */
                @Override
                public Map<String, String[]> getParameterMap()
                {
                    final Map<String, String[]> map = new HashMap<>(super.getParameterMap());
                    map.put(PARAM_USERNAME, this.getParameterValues(PARAM_USERNAME));
                    return map;
                }
            };

            // map existing credentials to the new user name
            final CredentialVault credentialVault = this.connectorService.getCredentialVault(session, userName);
            if (credentialVault != null)
            {
                final CredentialVault newCredentialVault = this.connectorService.getCredentialVault(session, effectiveUserName);
                for (final String storeId : credentialVault.getStoredIds())
                {
                    final Credentials credentials = credentialVault.retrieve(storeId);
                    final Credentials newCredentials = newCredentialVault.newCredentials(storeId);
                    newCredentials.setProperty(Credentials.CREDENTIAL_USERNAME, effectiveUserName);
                    newCredentials.setProperty(Credentials.CREDENTIAL_PASSWORD, credentials.getProperty(Credentials.CREDENTIAL_PASSWORD));
                }
            }
        }

        super.onSuccess(effectiveRequest, response);
    }

    /**
     * Attempts to load the effective user name for the authenticated user from the backend.
     *
     * @param request
     *            the servlet request being processed
     * @param session
     *            the currently active session
     * @param userId
     *            the ID of the user as provided by the user themselves
     * @return the effective user name or {@code null} if the effective user name could not be loaded for whatever reason (will be logged)
     */
    protected String loadEffectiveUserName(final HttpServletRequest request, final HttpSession session, final String userId)
    {
        String effectiveUserName;
        try
        {
            final Connector connector = this.connectorService.getConnector(AlfrescoUserFactory.ALFRESCO_ENDPOINT_ID, userId, session);

            final ConnectorContext c = new ConnectorContext(HttpMethod.GET);
            c.setContentType("application/json");
            final Response res = connector.call("/acosix/api/keycloak/effectiveUserName", c);

            if (res.getStatus().getCode() == Status.STATUS_OK)
            {
                final String responseText = res.getResponse();
                final JSONParser jsonParser = new JSONParser();
                final Object userData = jsonParser.parse(responseText.toString());
                if (userData instanceof JSONObject)
                {
                    effectiveUserName = (String) ((JSONObject) userData).get("userName");
                }
                else
                {
                    LOGGER.warn("Response in call to load effective user name for {} was not a proper JSON object", userId);
                    effectiveUserName = null;
                }
            }
            else
            {
                if (res.getStatus().getCode() == 401)
                {
                    LOGGER.debug("Failed to load effective user name for {} with backend call as authentication was not / no longer active",
                            userId);
                }
                else
                {
                    LOGGER.warn("Failed to load effective user name for {} with backend call resulting in HTTP response with status {} {}",
                            userId, res.getStatus().getCode(), res.getStatus().getMessage());
                }
                effectiveUserName = null;
            }
        }
        catch (final ConnectorServiceException | ParseException ex)
        {
            LOGGER.error("Failed to load effective user name for {}", userId, ex);
            effectiveUserName = null;
        }

        return effectiveUserName;
    }
}
