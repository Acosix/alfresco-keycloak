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
package de.acosix.alfresco.keycloak.share.config;

import org.springframework.extensions.config.ConfigElement;

import de.acosix.alfresco.utility.share.config.BaseCustomConfigElement;
import de.acosix.alfresco.utility.share.config.ConfigValueHolder;

/**
 *
 * @author Axel Faust
 */
public class KeycloakAuthenticationConfigElement extends BaseCustomConfigElement
{

    private static final long serialVersionUID = 8587583775593697136L;

    public static final String NAME = KeycloakConfigConstants.KEYCLOAK_AUTH_CONFIG_NAME;

    protected final ConfigValueHolder<Boolean> enhanceLoginForm = new ConfigValueHolder<>();

    protected final ConfigValueHolder<Boolean> enableSsoFilter = new ConfigValueHolder<>();

    protected final ConfigValueHolder<Boolean> forceKeycloakSso = new ConfigValueHolder<>();

    protected final ConfigValueHolder<Boolean> rememberKeycloakSso = new ConfigValueHolder<>();

    protected final ConfigValueHolder<Integer> bodyBufferLimit = new ConfigValueHolder<>();

    protected final ConfigValueHolder<Integer> sessionMapperLimit = new ConfigValueHolder<>();

    protected final ConfigValueHolder<Boolean> ignoreDefaultFilter = new ConfigValueHolder<>();

    protected final ConfigValueHolder<Boolean> performTokenExchange = new ConfigValueHolder<>();

    protected final ConfigValueHolder<String> alfrescoResourceName = new ConfigValueHolder<>();

    /**
     * Creates a new instance of this class.
     */
    public KeycloakAuthenticationConfigElement()
    {
        super(NAME);
    }

    /**
     * @param enhanceLoginForm
     *     the enhanceLoginForm to set
     */
    public void setEnhanceLoginForm(final Boolean enhanceLoginForm)
    {
        this.enhanceLoginForm.setValue(enhanceLoginForm);
    }

    /**
     * @return the enhanceLoginForm
     */
    public Boolean getEnhanceLoginForm()
    {
        return this.enhanceLoginForm.getValue();
    }

    /**
     * @param enableSsoFilter
     *     the enableSsoFilter to set
     */
    public void setEnableSsoFilter(final Boolean enableSsoFilter)
    {
        this.enableSsoFilter.setValue(enableSsoFilter);
    }

    /**
     * @return the enhanceSsoFilter
     */
    public Boolean getEnableSsoFilter()
    {
        return this.enableSsoFilter.getValue();
    }

    /**
     * @param forceKeycloakSso
     *     the forceKeycloakSso to set
     */
    public void setForceKeycloakSso(final Boolean forceKeycloakSso)
    {
        this.forceKeycloakSso.setValue(forceKeycloakSso);
    }

    /**
     * @return the forceKeycloakSso
     */
    public Boolean getForceKeycloakSso()
    {
        return this.forceKeycloakSso.getValue();
    }

    /**
     * @param rememberKeycloakSso
     *     the rememberKeycloakSso to set
     */
    public void setRememberKeycloakSso(final Boolean rememberKeycloakSso)
    {
        this.rememberKeycloakSso.setValue(rememberKeycloakSso);
    }

    /**
     * @return the rememberKeycloakSso
     */
    public Boolean getRememberKeycloakSso()
    {
        return this.rememberKeycloakSso.getValue();
    }

    /**
     * @param bodyBufferLimit
     *     the bodyBufferLimit to set
     */
    public void setBodyBufferLimit(final Integer bodyBufferLimit)
    {
        this.bodyBufferLimit.setValue(bodyBufferLimit);
    }

    /**
     * @return the bodyBufferLimit
     */
    public Integer getBodyBufferLimit()
    {
        return this.bodyBufferLimit.getValue();
    }

    /**
     * @param sessionMapperLimit
     *     the sessionMapperLimit to set
     */
    public void setSessionMapperLimit(final Integer sessionMapperLimit)
    {
        this.sessionMapperLimit.setValue(sessionMapperLimit);
    }

    /**
     * @return the sessionMapperLimit
     */
    public Integer getSessionMapperLimit()
    {
        return this.sessionMapperLimit.getValue();
    }

    /**
     * @param ignoreDefaultFilter
     *     the ignoreDefaultFilter to set
     */
    public void setIgnoreDefaultFilter(final Boolean ignoreDefaultFilter)
    {
        this.ignoreDefaultFilter.setValue(ignoreDefaultFilter);
    }

    /**
     * @return the ignoreDefaultFilter
     */
    public Boolean getIgnoreDefaultFilter()
    {
        return this.ignoreDefaultFilter.getValue();
    }

    /**
     * @param performTokenExchange
     *     the performTokenExchange to set
     */
    public void setPerformTokenExchange(final Boolean performTokenExchange)
    {
        this.performTokenExchange.setValue(performTokenExchange);
    }

    /**
     * @return the performTokenExchange
     */
    public Boolean getPerformTokenExchange()
    {
        return this.performTokenExchange.getValue();
    }

    /**
     * @param alfrescoResourceName
     *     the alfrescoResourceName to set
     */
    public void setAlfrescoResourceName(final String alfrescoResourceName)
    {
        this.alfrescoResourceName.setValue(alfrescoResourceName);
    }

    /**
     * @return the alfrescoResourceName
     */
    public String getAlfrescoResourceName()
    {
        return this.alfrescoResourceName.getValue();
    }

    /**
     *
     * {@inheritDoc}
     */
    @Override
    public ConfigElement combine(final ConfigElement configElement)
    {
        if (!(configElement instanceof KeycloakAuthenticationConfigElement))
        {
            throw new IllegalArgumentException("Cannot combine with " + configElement);
        }

        final KeycloakAuthenticationConfigElement combined = new KeycloakAuthenticationConfigElement();
        final KeycloakAuthenticationConfigElement otherConfigElement = (KeycloakAuthenticationConfigElement) configElement;

        if (otherConfigElement.enhanceLoginForm.isUnset())
        {
            combined.enhanceLoginForm.unset();
        }
        else
        {
            combined.setEnhanceLoginForm(otherConfigElement.getEnhanceLoginForm() != null ? otherConfigElement.getEnhanceLoginForm()
                    : this.getEnhanceLoginForm());
        }

        if (otherConfigElement.enhanceLoginForm.isUnset())
        {
            combined.enhanceLoginForm.unset();
        }
        else
        {
            combined.setEnableSsoFilter(
                    otherConfigElement.getEnableSsoFilter() != null ? otherConfigElement.getEnableSsoFilter() : this.getEnableSsoFilter());
        }

        if (otherConfigElement.forceKeycloakSso.isUnset())
        {
            combined.forceKeycloakSso.unset();
        }
        else
        {
            combined.setForceKeycloakSso(otherConfigElement.getForceKeycloakSso() != null ? otherConfigElement.getForceKeycloakSso()
                    : this.getForceKeycloakSso());
        }

        if (otherConfigElement.rememberKeycloakSso.isUnset())
        {
            combined.rememberKeycloakSso.unset();
        }
        else
        {
            combined.setRememberKeycloakSso(
                    otherConfigElement.getRememberKeycloakSso() != null ? otherConfigElement.getRememberKeycloakSso()
                            : this.getRememberKeycloakSso());
        }

        if (otherConfigElement.bodyBufferLimit.isUnset())
        {
            combined.bodyBufferLimit.unset();
        }
        else
        {
            combined.setBodyBufferLimit(
                    otherConfigElement.getBodyBufferLimit() != null ? otherConfigElement.getBodyBufferLimit() : this.getBodyBufferLimit());
        }

        if (otherConfigElement.sessionMapperLimit.isUnset())
        {
            combined.sessionMapperLimit.unset();
        }
        else
        {
            combined.setSessionMapperLimit(otherConfigElement.getSessionMapperLimit() != null ? otherConfigElement.getSessionMapperLimit()
                    : this.getSessionMapperLimit());
        }

        if (otherConfigElement.ignoreDefaultFilter.isUnset())
        {
            combined.ignoreDefaultFilter.unset();
        }
        else
        {
            combined.setIgnoreDefaultFilter(
                    otherConfigElement.getIgnoreDefaultFilter() != null ? otherConfigElement.getIgnoreDefaultFilter()
                            : this.getIgnoreDefaultFilter());
        }

        if (otherConfigElement.performTokenExchange.isUnset())
        {
            combined.performTokenExchange.unset();
        }
        else
        {
            combined.setPerformTokenExchange(
                    otherConfigElement.getPerformTokenExchange() != null ? otherConfigElement.getPerformTokenExchange()
                            : this.getPerformTokenExchange());
        }

        if (otherConfigElement.alfrescoResourceName.isUnset())
        {
            combined.alfrescoResourceName.unset();
        }
        else
        {
            combined.setAlfrescoResourceName(
                    otherConfigElement.getAlfrescoResourceName() != null ? otherConfigElement.getAlfrescoResourceName()
                            : this.getAlfrescoResourceName());
        }

        return combined;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public String toString()
    {
        final StringBuilder builder = new StringBuilder();
        builder.append("KeycloakAuthenticationConfigElement [");
        builder.append("enhanceLoginForm=");
        builder.append(this.enhanceLoginForm);
        builder.append(", ");
        builder.append("enableSsoFilter=");
        builder.append(this.enableSsoFilter);
        builder.append(", ");
        builder.append("forceKeycloakSso=");
        builder.append(this.forceKeycloakSso);
        builder.append(", ");
        builder.append("rememberKeycloakSso=");
        builder.append(this.rememberKeycloakSso);
        builder.append(", ");
        builder.append("bodyBufferLimit=");
        builder.append(this.bodyBufferLimit);
        builder.append(", ");
        builder.append("sessionMapperLimit=");
        builder.append(this.sessionMapperLimit);
        builder.append(", ");
        builder.append("ignoreDefaultFilter=");
        builder.append(this.ignoreDefaultFilter);
        builder.append(", ");
        builder.append("performTokenExchange=");
        builder.append(this.performTokenExchange);
        builder.append(", ");
        builder.append("alfrescoResourceName=");
        builder.append(this.alfrescoResourceName);
        builder.append("]");
        return builder.toString();
    }

}
