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
package de.acosix.alfresco.keycloak.repo.token;

/**
 * Instances of this class signal errors / problems verifying an access token retrieved from Keycloak.
 *
 * @author Axel Faust
 */
public class AccessTokenVerificationException extends AccessTokenException
{

    private static final long serialVersionUID = 6057892110861316386L;

    /**
     * Constructs a new instance of this class
     *
     * @param msgId
     *            the message i18n key or actual message for the exception
     */
    public AccessTokenVerificationException(final String msgId)
    {
        super(msgId);
    }

    /**
     * Constructs a new instance of this class
     *
     * @param msgId
     *            the message i18n key or actual message for the exception
     * @param cause
     *            the underlying cause of this exception
     */
    public AccessTokenVerificationException(final String msgId, final Throwable cause)
    {
        super(msgId, cause);
    }

    /**
     * Constructs a new instance of this class
     *
     * @param msgId
     *            the message i18n key or actual message for the exception
     * @param msgParams
     *            the parameters for constructing a human readable message based on pattern-based message
     */
    public AccessTokenVerificationException(final String msgId, final Object[] msgParams)
    {
        super(msgId, msgParams);
    }

    /**
     * Constructs a new instance of this class
     *
     * @param msgId
     *            the message i18n key or actual message for the exception
     * @param msgParams
     *            the parameters for constructing a human readable message based on pattern-based message
     * @param cause
     *            the underlying cause of this exception
     */
    public AccessTokenVerificationException(final String msgId, final Object[] msgParams, final Throwable cause)
    {
        super(msgId, msgParams, cause);
    }

}
