/*
 * Copyright 2019 - 2020 Acosix GmbH
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

import javax.servlet.ServletException;
import javax.servlet.http.HttpSession;

import org.alfresco.repo.SessionUser;
import org.alfresco.repo.webdav.auth.AuthenticationDriver;
import org.alfresco.repo.webdav.auth.BaseAuthenticationFilter;
import org.alfresco.web.app.servlet.WebscriptCookieAuthenticationFilter;

/**
 * This sub-class of the default web script cookie filter only exists to ensure the proper session attribute names are used for mapping the
 * authenticated session user.
 *
 * @author Axel Faust
 */
public class KeycloakWebScriptCookieAuthenticationFilter extends WebscriptCookieAuthenticationFilter
{

    /**
     *
     * {@inheritDoc}
     */
    @Override
    protected SessionUser createUserEnvironment(final HttpSession session, final String userName) throws IOException, ServletException
    {
        final SessionUser sessionUser = super.createUserEnvironment(session, userName);

        // ensure all common attribute names are mapped
        // Alfresco is really inconsistent with these attribute names
        session.setAttribute(AuthenticationDriver.AUTHENTICATION_USER, sessionUser);
        session.setAttribute(BaseAuthenticationFilter.AUTHENTICATION_USER, sessionUser);

        return sessionUser;
    }

    /**
     *
     * {@inheritDoc}
     */
    @Override
    protected SessionUser createUserEnvironment(final HttpSession session, final String userName, final String ticket,
            final boolean externalAuth) throws IOException, ServletException
    {
        final SessionUser sessionUser = super.createUserEnvironment(session, userName, ticket, externalAuth);

        // ensure all common attribute names are mapped
        // Alfresco is really inconsistent with these attribute names
        session.setAttribute(AuthenticationDriver.AUTHENTICATION_USER, sessionUser);
        session.setAttribute(BaseAuthenticationFilter.AUTHENTICATION_USER, sessionUser);

        return sessionUser;
    }
}
