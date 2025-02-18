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

import jakarta.servlet.http.HttpServletRequest;

import org.springframework.extensions.surf.RequestContext;
import org.springframework.extensions.surf.RequestContextUtil;
import org.springframework.extensions.surf.ServletUtil;
import org.springframework.extensions.surf.mvc.RequestContextInterceptor;
import org.springframework.extensions.surf.support.ThreadLocalRequestContext;
import org.springframework.web.context.request.ServletWebRequest;
import org.springframework.web.context.request.WebRequest;

/**
 * This specialisation of the request context interceptor exists only to ensure that a newly created request context is properly
 * {@link RequestContextUtil#populateRequestContext(org.springframework.extensions.surf.RequestContext, jakarta.servlet.http.HttpServletRequest)
 * populated} as to ensure that somewhat important data, such as the user object, is properly initialised.
 *
 * @author Axel Faust
 */
public class PopulatingRequestContextInterceptor extends RequestContextInterceptor
{

    /**
     *
     * {@inheritDoc}
     */
    @Override
    public void preHandle(final WebRequest request) throws Exception
    {
        super.preHandle(request);

        final RequestContext context = ThreadLocalRequestContext.getRequestContext();
        final HttpServletRequest servletRequest = ((ServletWebRequest) request).getRequest();

        // just to be safe - can apparently not always be guaranteed
        // (despite our call to RequestContextUtil.initRequestContext in KeycloakAuthenticationFilter#doFilter)
        // without this, UserFactory may fail to obtain Connector due to missing session (indirectly retrieved via request)
        if (ServletUtil.getRequest() == null)
        {
            ServletUtil.setRequest(servletRequest);
        }
        RequestContextUtil.populateRequestContext(context, servletRequest);
    }
}
