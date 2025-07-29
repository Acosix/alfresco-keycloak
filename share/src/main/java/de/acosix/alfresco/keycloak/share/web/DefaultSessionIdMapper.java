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

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.locks.ReentrantReadWriteLock;

import org.keycloak.adapters.spi.InMemorySessionIdMapper;
import org.keycloak.adapters.spi.SessionIdMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.extensions.config.ConfigService;

import de.acosix.alfresco.keycloak.share.config.KeycloakAuthenticationConfigElement;

/**
 * This implementation of a {@link SessionIdMapper Keycloak session ID mapper} is based on the {@link InMemorySessionIdMapper in-memory
 * mapper}, but uses a better model for synchronisation and respects configured size limits, ejecting least-recently active sessions first.
 * Activity of session with regards to being determined the "least-recently active" session is based upon validation calls to
 * {@link #hasSession(String) hasSession}.
 *
 * @author Axel Faust
 */
public class DefaultSessionIdMapper implements SessionIdMapper, InitializingBean
{

    private static final Logger LOGGER = LoggerFactory.getLogger(DefaultSessionIdMapper.class);

    private static final int DEFAULT_SESSION_COUNT_LIMIT = 1000;

    protected final ReentrantReadWriteLock lock = new ReentrantReadWriteLock(true);

    protected final Map<String, String> ssoToSession = new HashMap<>();

    protected final Map<String, String> sessionToSso = new HashMap<>();

    protected final Map<String, Set<String>> principalToSession = new HashMap<>();

    protected final Map<String, String> sessionToPrincipal = new HashMap<>();

    protected ConfigService configService;

    protected int sessionCountLimit = DEFAULT_SESSION_COUNT_LIMIT;

    protected Set<String> sessionUsedOrder;

    /**
     *
     * {@inheritDoc}
     */
    @Override
    public void afterPropertiesSet()
    {
        if (this.configService != null)
        {
            final KeycloakAuthenticationConfigElement keycloakAuthConfig = (KeycloakAuthenticationConfigElement) this.configService
                    .getConfig("Keycloak").getConfigElement(KeycloakAuthenticationConfigElement.NAME);
            final Integer sessionMapperLimit = keycloakAuthConfig.getSessionMapperLimit();
            if (sessionMapperLimit != null)
            {
                this.sessionCountLimit = sessionMapperLimit.intValue();
            }
        }

        if (this.sessionCountLimit <= 0)
        {
            LOGGER.warn(
                    "Session count limit is set to {} - session ID mapper will not restrict size of internal data structures (this can cause OOMEs)",
                    this.sessionCountLimit);
        }
        else
        {
            this.sessionUsedOrder = new LinkedHashSet<>();
        }
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
     * @param sessionCountLimit
     *            the sessionCountLimit to set
     */
    public void setSessionCountLimit(final int sessionCountLimit)
    {
        this.sessionCountLimit = sessionCountLimit;
    }

    @Override
    public boolean hasSession(final String id)
    {
        this.lock.readLock().lock();
        try
        {
            LOGGER.debug("Checking hasSession for {}", id);
            final boolean hasSession = this.sessionToSso.containsKey(id) || this.sessionToPrincipal.containsKey(id);
            LOGGER.debug("Session {}", hasSession ? "is mapped" : "is not mapped");

            if (hasSession && this.sessionCountLimit > 0)
            {
                synchronized (this.sessionUsedOrder)
                {
                    this.sessionUsedOrder.remove(id);
                    this.sessionUsedOrder.add(id);
                }
            }
            return hasSession;
        }
        finally
        {
            this.lock.readLock().unlock();
        }
    }

    /**
     *
     * {@inheritDoc}
     */
    @Override
    public void clear()
    {
        this.lock.writeLock().lock();
        try
        {
            LOGGER.info("Clearing all mappings");
            this.ssoToSession.clear();
            this.sessionToSso.clear();
            this.principalToSession.clear();
            this.sessionToPrincipal.clear();
        }
        finally
        {
            this.lock.writeLock().unlock();
        }
    }

    /**
     *
     * {@inheritDoc}
     */
    @Override
    public Set<String> getUserSessions(final String principal)
    {
        Set<String> userSessions;
        this.lock.readLock().lock();
        try
        {
            LOGGER.debug("Retrieving user sessions for {}", principal);
            final Set<String> lookup = this.principalToSession.get(principal);
            if (lookup != null)
            {
                userSessions = new HashSet<>();
                userSessions.addAll(lookup);
            }
            else
            {
                userSessions = Collections.emptySet();
            }
        }
        finally
        {
            this.lock.readLock().unlock();
        }
        LOGGER.debug("Principal {} is mapped to sessions {}", principal, userSessions);
        return userSessions;
    }

    /**
     *
     * {@inheritDoc}
     */
    @Override
    public String getSessionFromSSO(final String sso)
    {
        this.lock.readLock().lock();
        try
        {
            return this.ssoToSession.get(sso);
        }
        finally
        {
            this.lock.readLock().unlock();
        }
    }

    /**
     *
     * {@inheritDoc}
     */
    @Override
    public void map(final String sso, final String principal, final String session)
    {
        this.lock.writeLock().lock();
        try
        {
            LOGGER.debug("Adding mapping ({}, {},  {})", sso, principal, session);

            if (sso != null)
            {
                this.ssoToSession.put(sso, session);
                this.sessionToSso.put(session, sso);

            }

            if (principal != null)
            {
                this.principalToSession.compute(principal, (key, value) -> {
                    if (value == null)
                    {
                        value = new HashSet<>();
                    }
                    value.add(session);
                    return value;
                });
                this.sessionToPrincipal.put(session, principal);
            }

            if (this.sessionCountLimit > 0 && sso != null && principal != null)
            {
                synchronized (this.sessionUsedOrder)
                {
                    this.sessionUsedOrder.add(session);

                    final int sessionsToRemove = this.sessionUsedOrder.size() - this.sessionCountLimit;
                    if (sessionsToRemove == 1)
                    {
                        final String sessionToRemove = this.sessionUsedOrder.iterator().next();
                        this.removeSession(sessionToRemove);
                    }
                    // should really not happen, but in place should we ever switch to a more bulk-handling
                    else if (sessionsToRemove > 0)
                    {
                        final List<String> sessionsForRemoval = new ArrayList<>(this.sessionUsedOrder).subList(0, sessionsToRemove);
                        sessionsForRemoval.forEach(this::removeSession);
                    }
                }
            }
        }
        finally
        {
            this.lock.writeLock().unlock();
        }
    }

    /**
     *
     * {@inheritDoc}
     */
    @Override
    public void removeSession(final String session)
    {
        this.lock.writeLock().lock();
        try
        {
            LOGGER.debug("Removing session {}", session);

            final String sso = this.sessionToSso.remove(session);
            if (sso != null)
            {
                this.ssoToSession.remove(sso);
            }

            final String principal = this.sessionToPrincipal.remove(session);
            if (principal != null)
            {
                this.principalToSession.computeIfPresent(principal, (key, value) -> {
                    value.remove(session);
                    if (value.isEmpty())
                    {
                        value = null;
                    }
                    return value;
                });
            }

            if (this.sessionCountLimit > 0)
            {
                synchronized (this.sessionUsedOrder)
                {
                    this.sessionUsedOrder.remove(session);
                }
            }
        }
        finally
        {
            this.lock.writeLock().unlock();
        }
    }
}
