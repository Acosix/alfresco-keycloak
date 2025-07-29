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

import java.io.IOException;
import java.util.Date;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletContext;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;

import org.alfresco.util.PropertyCheck;
import org.alfresco.web.site.SlingshotUserFactory;
import org.alfresco.web.site.servlet.SlingshotLoginController;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.extensions.config.ConfigElement;
import org.springframework.extensions.config.ConfigService;
import org.springframework.extensions.surf.UserFactory;
import org.springframework.extensions.surf.exception.ConnectorServiceException;
import org.springframework.extensions.surf.site.AuthenticationUtil;
import org.springframework.extensions.surf.support.AlfrescoUserFactory;
import org.springframework.extensions.surf.util.URLEncoder;
import org.springframework.extensions.webscripts.Status;
import org.springframework.extensions.webscripts.connector.Connector;
import org.springframework.extensions.webscripts.connector.ConnectorContext;
import org.springframework.extensions.webscripts.connector.ConnectorService;
import org.springframework.extensions.webscripts.connector.HttpMethod;
import org.springframework.extensions.webscripts.connector.Response;
import org.springframework.extensions.webscripts.connector.User;
import org.springframework.extensions.webscripts.servlet.DependencyInjectedFilter;

/**
 * This filter performs the initial load of user groups for any user authenticated by a filter preceeding it in the filter chain, and
 * transparently refreshes the user groups after a configurable amount of time has past, in order to avoid Share user groups to become stale
 * / inconsistent with actual group memberships in the Alfresco Repository. This filter is necessary since the default logic for the simple
 * initialisation inside {@link SlingshotLoginController} is inaccessible to custom authentication filters, and there is actually no refresh
 * functionality in default Alfresco at all, which can be problematic for SSO-authenticated sessions that may be active for a long time.
 *
 * @author Axel Faust
 */
public class UserGroupsLoadFilter implements DependencyInjectedFilter, InitializingBean
{

    public static final String SESSION_ATTRIBUTE_KEY_USER_GROUPS_LAST_LOADED = SlingshotLoginController.SESSION_ATTRIBUTE_KEY_USER_GROUPS
            + "_lastLoaded";

    private static final Logger LOGGER = LoggerFactory.getLogger(UserGroupsLoadFilter.class);

    private static final long DEFAULT_CACHED_USER_GROUPS_TIMEOUT = 60000;

    protected ConfigService configService;

    protected ConnectorService connectorService;

    /**
     *
     * {@inheritDoc}
     */
    @Override
    public void afterPropertiesSet()
    {
        PropertyCheck.mandatory(this, "configService", this.configService);
        PropertyCheck.mandatory(this, "connectorService", this.connectorService);
    }

    /**
     * @param configService
     *            the configService to set
     */
    public void setConfigService(final ConfigService configService)
    {
        this.configService = configService;
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
    public void doFilter(final ServletContext context, final ServletRequest request, final ServletResponse response,
            final FilterChain chain) throws IOException, ServletException
    {
        if (request instanceof HttpServletRequest)
        {
            final HttpSession session = ((HttpServletRequest) request).getSession(false);
            if (session != null)
            {
                final String userId = AuthenticationUtil.getUserId((HttpServletRequest) request);
                final String userGroupsCSVList = (String) session.getAttribute(SlingshotLoginController.SESSION_ATTRIBUTE_KEY_USER_GROUPS);
                final User user = (User) session.getAttribute(UserFactory.SESSION_ATTRIBUTE_KEY_USER_OBJECT);

                final Date lastLoaded = (Date) session.getAttribute(SESSION_ATTRIBUTE_KEY_USER_GROUPS_LAST_LOADED);
                long cachedUserGroupsTimeout = DEFAULT_CACHED_USER_GROUPS_TIMEOUT;

                final ConfigElement userConfig = this.configService.getGlobalConfig().getConfigElement("user");
                if (userConfig != null)
                {
                    final String timeoutConfig = userConfig.getChildValue("cached-user-groups-timeout");
                    if (timeoutConfig != null)
                    {
                        cachedUserGroupsTimeout = Long.parseLong(timeoutConfig, 10);
                    }
                }

                if (userId != null)
                {
                    if (userGroupsCSVList == null
                            || (lastLoaded != null && lastLoaded.getTime() + cachedUserGroupsTimeout < System.currentTimeMillis()))
                    {
                        final String reloadedUserGroupsCSVList = this.loadUserGroupsCSVList((HttpServletRequest) request, session, userId);
                        if (reloadedUserGroupsCSVList != null)
                        {
                            session.setAttribute(SlingshotLoginController.SESSION_ATTRIBUTE_KEY_USER_GROUPS, reloadedUserGroupsCSVList);
                            if (user != null)
                            {
                                user.setProperty(SlingshotUserFactory.ALF_USER_GROUPS, reloadedUserGroupsCSVList);
                            }
                        }
                        else
                        {
                            LOGGER.debug(
                                    "User groups session attribute cannot be updated after failure to load - will retry after next cache timeout");
                            // some scripts (*cough* faceted-search) can fail if attribute is not set
                            if (session.getAttribute(SlingshotLoginController.SESSION_ATTRIBUTE_KEY_USER_GROUPS) == null)
                            {
                                session.setAttribute(SlingshotLoginController.SESSION_ATTRIBUTE_KEY_USER_GROUPS, "");
                            }
                            if (user != null && user.getProperty(SlingshotUserFactory.ALF_USER_GROUPS) == null)
                            {
                                user.setProperty(SlingshotUserFactory.ALF_USER_GROUPS, "");
                            }
                        }
                        session.setAttribute(SESSION_ATTRIBUTE_KEY_USER_GROUPS_LAST_LOADED, new Date());
                    }
                    else if (lastLoaded == null)
                    {
                        // might have just been loaded by an authentication filter on initial login
                        session.setAttribute(SESSION_ATTRIBUTE_KEY_USER_GROUPS_LAST_LOADED, new Date());
                    }
                }
            }
        }

        chain.doFilter(request, response);
    }

    /**
     * Loads the groups a user is a member of as a comma-separated list from the default Alfresco backend.
     *
     * @param request
     *            the HTTP servlet request
     * @param session
     *            the current session
     * @param userId
     *            the ID of the user for which to load the group memberships
     * @return the list of groups the user is a member of as a comma-separated list of names
     */
    protected String loadUserGroupsCSVList(final HttpServletRequest request, final HttpSession session, final String userId)
    {
        String userGroupsCSVList;
        try
        {
            // logic nearly identical to SlingshotLoginController
            final Connector connector = this.connectorService.getConnector(AlfrescoUserFactory.ALFRESCO_ENDPOINT_ID, userId, session);

            final ConnectorContext c = new ConnectorContext(HttpMethod.GET);
            c.setContentType("application/json");
            final Response res = connector.call("/api/people/" + URLEncoder.encode(userId) + "?groups=true", c);

            if (res.getStatus().getCode() == Status.STATUS_OK)
            {
                final String responseText = res.getResponse();
                final JSONParser jsonParser = new JSONParser();
                final Object userData = jsonParser.parse(responseText);

                final StringBuilder groups = new StringBuilder(512);
                if (userData instanceof JSONObject)
                {
                    final Object groupsArray = ((JSONObject) userData).get("groups");
                    if (groupsArray instanceof JSONArray)
                    {
                        for (final Object groupData : (JSONArray) groupsArray)
                        {
                            if (groupData instanceof JSONObject)
                            {
                                final Object groupName = ((JSONObject) groupData).get("itemName");
                                if (groupName != null)
                                {
                                    if (groups.length() > 0)
                                    {
                                        groups.append(',');
                                    }
                                    groups.append(groupName.toString());
                                }
                            }
                        }
                    }
                }

                userGroupsCSVList = groups.toString();

                LOGGER.debug("Retrieved group memberships for user {}: {}", userId, userGroupsCSVList);
            }
            else
            {
                if (res.getStatus().getCode() == 401)
                {
                    LOGGER.debug("Failed to load user groups for {} with backend call as authentication was not / no longer active",
                            userId);
                }
                else
                {
                    LOGGER.warn("Failed to load user groups for {} with backend call resulting in HTTP response with status {} {}", userId,
                            res.getStatus().getCode(), res.getStatus().getMessage());
                }
                userGroupsCSVList = null;
            }
        }
        catch (final ConnectorServiceException | ParseException ex)
        {
            LOGGER.error("Failed to load user groups for {}", userId, ex);
            userGroupsCSVList = null;
        }

        return userGroupsCSVList;
    }
}
