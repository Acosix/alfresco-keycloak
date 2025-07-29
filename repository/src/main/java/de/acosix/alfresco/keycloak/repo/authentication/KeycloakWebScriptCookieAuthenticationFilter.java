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
import jakarta.servlet.http.HttpSession;

import org.alfresco.repo.SessionUser;
import org.alfresco.repo.web.scripts.bean.LoginPost;
import org.alfresco.web.app.servlet.WebscriptCookieAuthenticationFilter;

/**
 * This sub-class of the default web script cookie filter only exists to ensure that the filter does NOT completely intercept the call for
 * the {@link LoginPost login web script}, otherwise clients relying on the response body may not function correctly, and that it ensures
 * proper any previously existing session is invalidated when the login web script is called with explicit credentials.
 *
 * @author Axel Faust
 */
public class KeycloakWebScriptCookieAuthenticationFilter extends WebscriptCookieAuthenticationFilter
{

    // copied from base class - inaccessible otherwise
    private static final String API_LOGIN = "/api/login";

    /**
     *
     * {@inheritDoc}
     */
    @Override
    public void doFilter(final ServletContext context, final ServletRequest sreq, final ServletResponse sresp, final FilterChain chain)
            throws IOException, ServletException
    {
        final HttpServletRequest req = (HttpServletRequest) sreq;

        if (API_LOGIN.equals(req.getPathInfo()) && req.getMethod().equalsIgnoreCase("POST"))
        {
            final HttpSession session = req.getSession(false);
            if (session != null)
            {
                session.invalidate();
            }

            // from here on the default web script will handle things, including - most importantly - the response instead of 204 no content
            // response by base class
            chain.doFilter(req, sresp);
        }
        else
        {
            chain.doFilter(sreq, sresp);
        }
    }

    /**
     *
     * {@inheritDoc}
     */
    @Override
    protected SessionUser createUserEnvironment(final HttpSession session, final String userName) throws IOException, ServletException
    {
        throw new UnsupportedOperationException("Should never be called");
    }

    /**
     *
     * {@inheritDoc}
     */
    @Override
    protected SessionUser createUserEnvironment(final HttpSession session, final String userName, final String ticket,
            final boolean externalAuth) throws IOException, ServletException
    {
        throw new UnsupportedOperationException("Should never be called");
    }
}
