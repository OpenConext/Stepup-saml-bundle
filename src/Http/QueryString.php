<?php

/**
 * Copyright 2016 SURFnet B.V.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

namespace Surfnet\SamlBundle\Http;

use Surfnet\SamlBundle\Exception\RuntimeException;
use Surfnet\SamlBundle\SAML2\AuthnRequest;
use Symfony\Component\HttpFoundation\Request;

final class QueryString
{
    /**
     * @var array
     */
    private $parameters = [];

    /**
     * @param Request $request
     * @return QueryString
     */
    public static function fromHttpRequest(Request $request)
    {
        $queryString = new self;

        list(, $query)   = explode('?', $request->getRequestUri());
        $queryParamPairs = explode('&', $query);

        foreach ($queryParamPairs as $queryParamPair) {
            if (strpos($queryParamPair, '=') === false) {
                throw new RuntimeException('Could not parse signed request query: it does not contain key-value pairs');
            }

            list($key, $value) = explode('=', $queryParamPair, 2);
            $queryString->parameters[$key][] = $value;
        }

        return $queryString;
    }

    /**
     * @param string $parameterName
     * @return int
     */
    public function countParameter($parameterName)
    {
        if (!isset($this->parameters[$parameterName])) {
            return 0;
        }

        return count($this->parameters[$parameterName]);
    }

    /**
     * @return string
     */
    public function getSignedRequestQuery()
    {
        $httpQuery = AuthnRequest::PARAMETER_REQUEST . '=' . $this->parameters[AuthnRequest::PARAMETER_REQUEST][0];

        if (isset($this->parameters[AuthnRequest::PARAMETER_RELAY_STATE])) {
            $httpQuery .= '&'.AuthnRequest::PARAMETER_RELAY_STATE . '='
                . $this->parameters[AuthnRequest::PARAMETER_RELAY_STATE][0];
        }

        $httpQuery .= '&' . AuthnRequest::PARAMETER_SIGNATURE_ALGORITHM . '='
            . $this->parameters[AuthnRequest::PARAMETER_SIGNATURE_ALGORITHM][0];

        return $httpQuery;
    }
}
