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
package de.acosix.alfresco.keycloak.repo.sync;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.function.Predicate;

import org.alfresco.repo.security.sync.NodeDescription;
import org.alfresco.service.namespace.NamespaceService;
import org.alfresco.service.namespace.QName;
import org.alfresco.util.PropertyCheck;
import org.springframework.beans.factory.InitializingBean;

/**
 * This class provides common configuration properties and logic for mapping processor handling Keycloak authority attributes.
 *
 * @author Axel Faust
 */
public abstract class BaseAttributeProcessor implements InitializingBean
{

    protected NamespaceService namespaceService;

    protected int priority = 50;

    protected boolean mapBlankString;

    protected boolean mapNull;

    protected Map<String, String> attributes;

    protected Map<String, QName> attributePropertyQNameMappings;

    /**
     *
     * {@inheritDoc}
     */
    @Override
    public void afterPropertiesSet()
    {
        PropertyCheck.mandatory(this, "namespaceService", this.namespaceService);

        if (this.attributes != null && !this.attributes.isEmpty())
        {
            this.attributePropertyQNameMappings = new HashMap<>();
            this.attributes.forEach((k, v) -> this.attributePropertyQNameMappings.put(k, QName.resolveToQName(this.namespaceService, v)));
        }
    }

    /**
     * @param namespaceService
     *     the namespaceService to set
     */
    public void setNamespaceService(final NamespaceService namespaceService)
    {
        this.namespaceService = namespaceService;
    }

    /**
     * @param priority
     *     the priority to set
     */
    public void setPriority(final int priority)
    {
        this.priority = priority;
    }

    /**
     * @param attributes
     *     the attributes to set
     */
    public void setAttributes(final Map<String, String> attributes)
    {
        this.attributes = attributes;
    }

    /**
     * @param mapBlankString
     *     the mapBlankString to set
     */
    public void setMapBlankString(final boolean mapBlankString)
    {
        this.mapBlankString = mapBlankString;
    }

    /**
     * @param mapNull
     *     the mapNull to set
     */
    public void setMapNull(final boolean mapNull)
    {
        this.mapNull = mapNull;
    }

    /**
     * Performs the general attribute to property mapping. This operation will not handle any value type conversions, relying instead on the
     * underlying data types and registered type converters in Alfresco to handle conversion in the persistence layer. Any attribute which
     * is only associated with a single value will be unwrapped from a list to the singular value, while all other attributes will be kept
     * as-is. THis operation also does not perform any checks whether a configured target property actually supports a multi-valued
     * property, again leaving that kind of processing to the Alfresco default functionality of integrity checking.
     *
     * @param attributes
     *     the list of attributes
     * @param nodeDescription
     *     the node description to enhance
     */
    protected void map(final Map<String, List<String>> attributes, final NodeDescription nodeDescription)
    {
        if (this.attributePropertyQNameMappings != null && attributes != null)
        {
            attributes.keySet().stream().filter(this.attributePropertyQNameMappings::containsKey)
                    .forEach(k -> this.mapAttribute(k, attributes, nodeDescription));
        }
    }

    /**
     * Maps an individual attribute to the correlating node property of the node description.
     *
     * @param attribute
     *     the name of the attribute to map
     * @param attributes
     *     the list of attributes
     * @param nodeDescription
     *     the node description to enhance
     */
    protected void mapAttribute(final String attribute, final Map<String, List<String>> attributes, final NodeDescription nodeDescription)
    {
        final QName propertyQName = this.attributePropertyQNameMappings.get(attribute);
        final List<String> values = attributes.get(attribute);
        if (values != null)
        {
            Serializable value;
            if (values.size() == 1)
            {
                value = values.get(0);
                if (!this.mapBlankString && ((String) value).isBlank())
                {
                    value = null;
                }
            }
            else
            {
                if (!this.mapBlankString)
                {
                    value = new ArrayList<>(values.stream().filter(Predicate.not(String::isBlank)).toList());
                    if (((List<?>) value).isEmpty())
                    {
                        value = null;
                    }
                }
                else
                {
                    value = new ArrayList<>(values);
                }
            }
            if (value != null || this.mapNull)
            {
                nodeDescription.getProperties().put(propertyQName, value);
            }
        }
        else if (this.mapNull)
        {
            nodeDescription.getProperties().put(propertyQName, null);
        }
    }

    protected Optional<String> mapAuthorityName(final QName authorityNameProperty, final Map<String, List<String>> attributes)
    {
        final Optional<String> result;
        final String attribute = this.attributePropertyQNameMappings.entrySet().stream()
                .filter((final Map.Entry<String, QName> e) -> authorityNameProperty.equals(e.getValue())).findFirst().map(Map.Entry::getKey)
                .orElse(null);
        if (attribute != null)
        {
            List<String> attrValues = attributes.get(attribute);
            if (attrValues != null && !this.mapBlankString)
            {
                attrValues = attrValues.stream().filter(Predicate.not(String::isBlank)).toList();
            }

            if (attrValues != null && attrValues.size() == 1)
            {
                result = Optional.of(attrValues.get(0));
            }
            else
            {
                result = Optional.empty();
            }
        }
        else
        {
            result = Optional.empty();
        }
        return result;
    }
}
