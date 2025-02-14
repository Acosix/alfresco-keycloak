/*
 * Copyright 2019 - 2021 Acosix GmbH
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

import java.io.ByteArrayOutputStream;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import jakarta.servlet.http.HttpServletRequest;

import org.alfresco.util.Pair;
import org.keycloak.adapters.servlet.ServletHttpFacade;
import org.keycloak.adapters.spi.HttpFacade;

/**
 * This {@link HttpFacade} wraps servlet requests and responses in such a way that any response headers / cookies being set by Keycloak
 * authenticators are captured, and otherwise no output is written to the servlet response. This is required for some scenarios in which a
 * redirect action should be included in the login form.
 *
 * @author Axel Faust
 */
public class ResponseHeaderCookieCaptureServletHttpFacade extends ServletHttpFacade
{

    protected final Map<Pair<String, String>, jakarta.servlet.http.Cookie> cookies = new HashMap<>();

    protected final Map<String, List<String>> headers = new HashMap<>();

    protected int status = -1;

    protected String message;

    /**
     * Creates a new instance of this class for the provided servlet request.
     *
     * @param request
     *            the servlet request to facade
     */
    public ResponseHeaderCookieCaptureServletHttpFacade(final HttpServletRequest request)
    {
        super(request, null);
    }

    /**
     *
     * {@inheritDoc}
     */
    @Override
    public Response getResponse()
    {
        return new ResponseCaptureFacade();
    }

    /**
     * @return the cookies
     */
    public List<jakarta.servlet.http.Cookie> getCookies()
    {
        return new ArrayList<>(this.cookies.values());
    }

    /**
     * @return the headers
     */
    public Map<String, List<String>> getHeaders()
    {
        final Map<String, List<String>> headers = new HashMap<>();
        this.headers.forEach((headerName, values) -> headers.put(headerName, new ArrayList<>(values)));
        return headers;
    }

    /**
     * @return the status
     */
    public int getStatus()
    {
        return this.status;
    }

    /**
     * @return the message
     */
    public String getMessage()
    {
        return this.message;
    }

    /**
     *
     * @author Axel Faust
     */
    private class ResponseCaptureFacade implements Response
    {

        /**
         *
         * {@inheritDoc}
         */
        @Override
        public void setStatus(final int status)
        {
            // NO-OP
        }

        /**
         *
         * {@inheritDoc}
         */
        @Override
        public void addHeader(final String name, final String value)
        {
            ResponseHeaderCookieCaptureServletHttpFacade.this.headers.computeIfAbsent(name, key -> new ArrayList<>()).add(value);
        }

        /**
         *
         * {@inheritDoc}
         */
        @Override
        public void setHeader(final String name, final String value)
        {
            ResponseHeaderCookieCaptureServletHttpFacade.this.headers.put(name, new ArrayList<>(Collections.singleton(value)));
        }

        /**
         *
         * {@inheritDoc}
         */
        @Override
        public void resetCookie(final String name, final String path)
        {
            ResponseHeaderCookieCaptureServletHttpFacade.this.cookies.remove(new Pair<>(name, path));
        }

        /**
         *
         * {@inheritDoc}
         */
        @Override
        public void setCookie(final String name, final String value, final String path, final String domain, final int maxAge,
                final boolean secure, final boolean httpOnly)
        {
            final jakarta.servlet.http.Cookie cookie = new jakarta.servlet.http.Cookie(name, value);
            cookie.setPath(path);
            if (domain != null)
            {
                cookie.setDomain(domain);
            }
            cookie.setMaxAge(maxAge);
            cookie.setSecure(secure);
            cookie.setHttpOnly(httpOnly);
            ResponseHeaderCookieCaptureServletHttpFacade.this.cookies.put(new Pair<>(name, path), cookie);
        }

        /**
         *
         * {@inheritDoc}
         */
        @Override
        public OutputStream getOutputStream()
        {
            return new ByteArrayOutputStream();
        }

        /**
         *
         * {@inheritDoc}
         */
        @Override
        public void sendError(final int code)
        {
            ResponseHeaderCookieCaptureServletHttpFacade.this.status = code;
        }

        /**
         *
         * {@inheritDoc}
         */
        @Override
        public void sendError(final int code, final String message)
        {
            ResponseHeaderCookieCaptureServletHttpFacade.this.status = code;
            ResponseHeaderCookieCaptureServletHttpFacade.this.message = message;
        }

        /**
         *
         * {@inheritDoc}
         */
        @Override
        public void end()
        {
            // NO-OP
        }
    }
}
