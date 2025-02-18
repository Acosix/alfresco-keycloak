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

import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * Instances of this class represent error details from Keycloak responses.
 *
 * @author Axel Faust
 */
public class ErrorResponse
{

    @JsonProperty("error")
    protected String error;

    @JsonProperty("error_description")
    protected String errorDescription;

    /**
     * @return the error
     */
    public String getError()
    {
        return this.error;
    }

    /**
     * @param error
     *            the error to set
     */
    public void setError(final String error)
    {
        this.error = error;
    }

    /**
     * @return the errorDescription
     */
    public String getErrorDescription()
    {
        return this.errorDescription;
    }

    /**
     * @param errorDescription
     *            the errorDescription to set
     */
    public void setErrorDescription(final String errorDescription)
    {
        this.errorDescription = errorDescription;
    }

}
