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

import java.io.IOException;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletContext;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;

import org.alfresco.repo.management.subsystems.ActivateableBean;
import org.alfresco.repo.web.filter.beans.DependencyInjectedFilter;
import org.alfresco.repo.webdav.auth.BaseAuthenticationFilter;
import org.alfresco.util.PropertyCheck;
import org.alfresco.web.app.servlet.WebScriptSSOAuthenticationFilter;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.extensions.webscripts.Description.RequiredAuthentication;
import org.springframework.extensions.webscripts.Match;
import org.springframework.extensions.webscripts.RuntimeContainer;

/**
 * This web script SSO authentication filter class is used instead of {@link WebScriptSSOAuthenticationFilter default Alfresco filter} in
 * order to properly handle unauthenticated and guest access, especially since the later is performed by Alfresco Share to load edition
 * details and potentially other data needed for determining which customisations are active, even before a user has had a chance to
 * authenticate.
 *
 * Note: Due to how default Alfresco {@code web.xml} wires up authentication filters, this filter cannot handle Public v1 ReST API web
 * scripts.
 *
 * @author Axel Faust
 */
public class KeycloakWebScriptSSOAuthenticationFilter extends BaseAuthenticationFilter
        implements DependencyInjectedFilter, InitializingBean, ActivateableBean
{

    // copied from WebScriptRequestImpl due to accessible constraints
    private static final String ARG_GUEST = "guest";

    private static final Logger LOGGER = LoggerFactory.getLogger(KeycloakWebScriptSSOAuthenticationFilter.class);

    protected RuntimeContainer container;

    protected boolean isActive = true;

    /**
     *
     * {@inheritDoc}
     */
    @Override
    public void afterPropertiesSet()
    {
        PropertyCheck.mandatory(this, "container", this.container);
    }

    /**
     * @param container
     *            the container to set
     */
    public void setContainer(final RuntimeContainer container)
    {
        this.container = container;
    }

    /**
     * Activates or deactivates the bean
     *
     * @param active
     *            <code>true</code> if the bean is active and initialisation should complete
     */
    public final void setActive(final boolean active)
    {
        this.isActive = active;
    }

    /**
     *
     * {@inheritDoc}
     */
    @Override
    public final boolean isActive()
    {
        return this.isActive;
    }

    /**
     *
     * {@inheritDoc}
     */
    @Override
    public void doFilter(final ServletContext context, final ServletRequest sreq, final ServletResponse sresp, final FilterChain chain)
            throws IOException, ServletException
    {
        final HttpServletRequest req = (HttpServletRequest) sreq;
        final String pathInfo = req.getPathInfo();

        LOGGER.debug("Processing request: {} SID: {}", pathInfo, req.getSession(false) != null ? req.getSession().getId() : null);

        final Match match = this.container.getRegistry().findWebScript(req.getMethod(), pathInfo);
        if (match != null && match.getWebScript() != null)
        {
            final RequiredAuthentication reqAuth = match.getWebScript().getDescription().getRequiredAuthentication();
            if (RequiredAuthentication.none == reqAuth)
            {
                LOGGER.debug("Found webscript with no authentication - set NO_AUTH_REQUIRED flag.");
                req.setAttribute(NO_AUTH_REQUIRED, Boolean.TRUE);
            }
            else if (RequiredAuthentication.guest == reqAuth && Boolean.parseBoolean(sreq.getParameter(ARG_GUEST)))
            {
                LOGGER.debug("Found webscript with guest authentication and request with set guest parameter - set NO_AUTH_REQUIRED flag.");
                req.setAttribute(NO_AUTH_REQUIRED, Boolean.TRUE);
            }
        }

        chain.doFilter(sreq, sresp);
    }

    /**
     *
     * {@inheritDoc}
     */
    @Override
    // ugh - Commons Logging - why does base class not have a sensible default??
    protected Log getLogger()
    {
        return LogFactory.getLog(this.getClass());
    }
}
