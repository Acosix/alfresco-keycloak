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

import java.lang.reflect.InvocationTargetException;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;

import org.alfresco.error.AlfrescoRuntimeException;
import org.dom4j.Element;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.extensions.config.ConfigElement;
import org.springframework.extensions.config.xml.elementreader.ConfigElementReader;

/**
 * @author Axel Faust
 */
public class KeycloakAdapterConfigElementReader implements ConfigElementReader
{

    private static final Logger LOGGER = LoggerFactory.getLogger(KeycloakAdapterConfigElementReader.class);

    /**
     * {@inheritDoc}
     */
    @Override
    public ConfigElement parse(final Element element)
    {
        final KeycloakAdapterConfigElement configElement = new KeycloakAdapterConfigElement();

        @SuppressWarnings("unchecked")
        final Iterator<Element> subElementIterator = element.elementIterator();
        while (subElementIterator.hasNext())
        {
            final Element subElement = subElementIterator.next();
            final String subElementName = subElement.getName();
            if (configElement.isFieldSupported(subElementName))
            {
                final Class<?> valueType = configElement.getFieldValueType(subElementName);

                if (Map.class.equals(valueType))
                {
                    final Map<String, Object> configMap = new HashMap<>();

                    @SuppressWarnings("unchecked")
                    final Iterator<Element> mapElementIterator = subElement.elementIterator();
                    while (mapElementIterator.hasNext())
                    {
                        final Element mapElement = mapElementIterator.next();
                        final String key = mapElement.getName();
                        final String value = mapElement.getTextTrim();

                        configMap.put(key, value);
                    }

                    configElement.setFieldValue(subElementName, configMap);
                }
                else
                {
                    final String textTrim = subElement.getTextTrim();
                    if (textTrim.isEmpty())
                    {
                        configElement.removeFieldValue(subElementName, true);
                    }
                    else if (Number.class.isAssignableFrom(valueType))
                    {
                        try
                        {
                            configElement.setFieldValue(subElementName,
                                    valueType.getMethod("valueOf", String.class).invoke(null, textTrim));
                        }
                        catch (final NoSuchMethodException | IllegalAccessException | InvocationTargetException ex)
                        {
                            LOGGER.error(
                                    "Number-based value type {} does not provide a publicly accessible, static valueOf to handle conversion of value {}",
                                    valueType, textTrim);
                            throw new AlfrescoRuntimeException("Failed to convert configuration value " + textTrim, ex);
                        }
                    }
                    else if (Boolean.class.equals(valueType))
                    {
                        configElement.setFieldValue(subElementName, Boolean.valueOf(textTrim));
                    }
                    else if (Character.class.equals(valueType))
                    {
                        if (textTrim.length() > 1)
                        {
                            throw new IllegalStateException("Value " + textTrim + " has more than one character");
                        }
                        configElement.setFieldValue(subElementName, Character.valueOf(textTrim.charAt(0)));
                    }
                    else if (String.class.equals(valueType))
                    {
                        configElement.setFieldValue(subElementName, textTrim);
                    }
                    else
                    {
                        throw new UnsupportedOperationException("Unsupported value type " + valueType);
                    }
                }
            }
            else
            {
                LOGGER.warn("Encountered unsupported Keycloak Adapter config element {}", subElementName);
            }
        }
        LOGGER.debug("Read configuration element {} from XML section", configElement);

        return configElement;
    }

}
