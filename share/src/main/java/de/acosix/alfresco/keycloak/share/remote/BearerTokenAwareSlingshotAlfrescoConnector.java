/*
 * Copyright 2019 Acosix GmbH
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
package de.acosix.alfresco.keycloak.share.remote;

import java.util.Collections;

import org.alfresco.web.site.servlet.SlingshotAlfrescoConnector;
import org.springframework.extensions.config.RemoteConfigElement.ConnectorDescriptor;
import org.springframework.extensions.webscripts.connector.ConnectorContext;
import org.springframework.extensions.webscripts.connector.ConnectorSession;
import org.springframework.extensions.webscripts.connector.RemoteClient;

/**
 * @author Axel Faust
 */
public class BearerTokenAwareSlingshotAlfrescoConnector extends SlingshotAlfrescoConnector
{

    public static final String CS_PARAM_BEARER_TOKEN = "bearerToken";

    /**
     * Constructs a new instance of this class.
     *
     * @param descriptor
     *            the descriptor / configuration of this connector
     * @param endpoint
     *            the endpoint with which this connector instance should connect
     */
    public BearerTokenAwareSlingshotAlfrescoConnector(final ConnectorDescriptor descriptor, final String endpoint)
    {
        super(descriptor, endpoint);
    }

    /**
     *
     * {@inheritDoc}
     */
    @Override
    protected void applyRequestHeaders(final RemoteClient remoteClient, final ConnectorContext context)
    {
        // apply default mapping of headers
        super.applyRequestHeaders(remoteClient, context);

        final ConnectorSession connectorSession = this.getConnectorSession();
        if (connectorSession != null)
        {
            final String bearerToken = connectorSession.getParameter(CS_PARAM_BEARER_TOKEN);
            if (bearerToken != null && !bearerToken.trim().isEmpty())
            {
                remoteClient.setRequestProperties(Collections.singletonMap("Authorization", "Bearer " + bearerToken));
            }
        }
    }
}
