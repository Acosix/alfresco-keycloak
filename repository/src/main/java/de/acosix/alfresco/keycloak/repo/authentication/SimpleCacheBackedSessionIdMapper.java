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

import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

import org.alfresco.repo.cache.SimpleCache;
import org.alfresco.util.PropertyCheck;
import org.keycloak.adapters.spi.SessionIdMapper;
import org.springframework.beans.factory.InitializingBean;

/**
 * @author Axel Faust
 */
public class SimpleCacheBackedSessionIdMapper implements SessionIdMapper, InitializingBean
{

    protected SimpleCache<String, String> ssoToSession;

    protected SimpleCache<String, String> sessionToSso;

    protected SimpleCache<String, Set<String>> principalToSession;

    protected SimpleCache<String, String> sessionToPrincipal;

    /**
     * {@inheritDoc}
     */
    @Override
    public void afterPropertiesSet()
    {
        PropertyCheck.mandatory(this, "ssoToSession", this.ssoToSession);
        PropertyCheck.mandatory(this, "sessionToSso", this.sessionToSso);
        PropertyCheck.mandatory(this, "principalToSession", this.principalToSession);
        PropertyCheck.mandatory(this, "sessionToPrincipal", this.sessionToPrincipal);
    }

    /**
     * @param ssoToSession
     *            the ssoToSession to set
     */
    public void setSsoToSession(final SimpleCache<String, String> ssoToSession)
    {
        this.ssoToSession = ssoToSession;
    }

    /**
     * @param sessionToSso
     *            the sessionToSso to set
     */
    public void setSessionToSso(final SimpleCache<String, String> sessionToSso)
    {
        this.sessionToSso = sessionToSso;
    }

    /**
     * @param principalToSession
     *            the principalToSession to set
     */
    public void setPrincipalToSession(final SimpleCache<String, Set<String>> principalToSession)
    {
        this.principalToSession = principalToSession;
    }

    /**
     * @param sessionToPrincipal
     *            the sessionToPrincipal to set
     */
    public void setSessionToPrincipal(final SimpleCache<String, String> sessionToPrincipal)
    {
        this.sessionToPrincipal = sessionToPrincipal;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public boolean hasSession(final String id)
    {
        final boolean hasSession = this.sessionToSso.contains(id) || this.sessionToPrincipal.contains(id);
        return hasSession;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void clear()
    {
        this.ssoToSession.clear();
        this.sessionToSso.clear();
        this.principalToSession.clear();
        this.sessionToPrincipal.clear();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Set<String> getUserSessions(final String principal)
    {
        Set<String> userSessions = Collections.emptySet();
        final Set<String> lookup = this.principalToSession.get(principal);
        if (lookup != null)
        {
            userSessions = new HashSet<>(lookup);
        }
        return userSessions;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public String getSessionFromSSO(final String sso)
    {
        return this.ssoToSession.get(sso);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void map(final String sso, final String principal, final String session)
    {
        if (sso != null)
        {
            this.ssoToSession.put(sso, session);
            this.sessionToSso.put(session, sso);
        }

        if (principal != null)
        {
            Set<String> userSessions = this.principalToSession.get(principal);
            if (userSessions == null)
            {
                userSessions = new HashSet<>();
                this.principalToSession.put(principal, userSessions);

            }
            userSessions.add(session);
            this.sessionToPrincipal.put(session, principal);
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void removeSession(final String session)
    {
        final String sso = this.sessionToSso.get(session);
        this.sessionToSso.remove(session);
        if (sso != null)
        {
            this.ssoToSession.remove(sso);
        }
        final String principal = this.sessionToPrincipal.get(session);
        this.sessionToPrincipal.remove(session);
        if (principal != null)
        {
            final Set<String> sessions = this.principalToSession.get(principal);
            sessions.remove(session);
            if (sessions.isEmpty())
            {
                this.principalToSession.remove(principal);
            }
        }
    }

}
