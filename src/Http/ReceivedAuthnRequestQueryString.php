<?php

/**
 * Copyright 2017 SURFnet B.V.
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
use Surfnet\SamlBundle\Http\Exception\InvalidReceivedAuthnRequestQueryStringException;
use Surfnet\SamlBundle\Http\Exception\InvalidRequestException;

final class ReceivedAuthnRequestQueryString
{
    const PARAMETER_REQUEST = 'SAMLRequest';
    const PARAMETER_SIGNATURE = 'Signature';
    const PARAMETER_SIGNATURE_ALGORITHM = 'SigAlg';
    const PARAMETER_RELAY_STATE = 'RelayState';

    private static $samlParameters = [
        self::PARAMETER_REQUEST,
        self::PARAMETER_SIGNATURE,
        self::PARAMETER_SIGNATURE_ALGORITHM,
        self::PARAMETER_RELAY_STATE,
    ];

    /**
     * @var string
     */
    private $samlRequest;

    /**
     * @var string|null
     */
    private $signature;

    /**
     * @var string|null
     */
    private $signatureAlgorithm;

    /**
     * @var string|null
     */
    private $relayState;

    private function __construct($samlRequest)
    {
        $this->samlRequest = $samlRequest;
    }

    /**
     * @param string $requestUri
     * @return ReceivedAuthnRequestQueryString
     *
     * @SuppressWarnings(PHPMD.CyclomaticComplexity) Extensive validation
     * @SuppressWarnings(PHPMD.NPathComplexity) Extensive validation
     */
    public static function parse($requestUri)
    {
        if (!is_string($requestUri) || strlen($requestUri) <= strlen('?SAMLRequest=')) {
            throw new InvalidReceivedAuthnRequestQueryStringException(sprintf(
                'Could not parse query string: expected a non-empty string of at least %d characters, %s given',
                strlen('?SAMLRequest='),
                is_object($requestUri) ? get_class($requestUri) : gettype($requestUri)
            ));
        }

        if (strpos($requestUri, '?') === false) {
            throw new InvalidReceivedAuthnRequestQueryStringException(sprintf(
                'Could not parse query string: given string ("%s") does not contain a query string separator',
                $requestUri
            ));
        }

        list(, $queryString) = explode('?', $requestUri);
        $queryParameters = explode('&', $queryString);

        $parameters = [];
        foreach ($queryParameters as $queryParameter) {
            if (!(strpos($queryParameter, '=') > 0)) {
                throw new InvalidReceivedAuthnRequestQueryStringException(sprintf(
                    'Could not parse "%s": it does not contain a valid key-value pair',
                    $queryParameter
                ));
            }

            list($key, $value) = explode('=', $queryParameter, 2);

            if (!in_array($key, self::$samlParameters)) {
                continue;
            }

            if (array_key_exists($key, $parameters)) {
                throw new InvalidReceivedAuthnRequestQueryStringException(sprintf(
                    'Invalid ReceivedAuthnRequest query string ("%s"): parameter "%s" already present',
                    $queryString,
                    $key
                ));
            }

            $parameters[$key] = $value;
        }

        if (!isset($parameters[self::PARAMETER_REQUEST])) {
            throw new InvalidReceivedAuthnRequestQueryStringException(sprintf(
                'Invalid ReceivedAuthnRequest query string ("%s"): parameter "%s" not found',
                $queryString,
                self::PARAMETER_REQUEST
            ));
        }

        if (base64_decode(urldecode($parameters[self::PARAMETER_REQUEST]), true) === false) {
            throw new InvalidRequestException('Failed decoding SAML request, did not receive a valid base64 string');
        }

        $parsedQueryString = new self($parameters[self::PARAMETER_REQUEST]);

        if (isset($parameters[self::PARAMETER_RELAY_STATE])) {
            $parsedQueryString->relayState = $parameters[self::PARAMETER_RELAY_STATE];
        }
        if (isset($parameters[self::PARAMETER_SIGNATURE])) {
            if (base64_decode(urldecode($parameters[self::PARAMETER_SIGNATURE]), true) === false) {
                throw new InvalidReceivedAuthnRequestQueryStringException(sprintf(
                    'Invalid ReceivedAuthnRequest query string ("%s"): signature is not base64 encoded correctly',
                    $queryString
                ));
            }

            $parsedQueryString->signature = $parameters[self::PARAMETER_SIGNATURE];
        }
        if (isset($parameters[self::PARAMETER_SIGNATURE_ALGORITHM])) {
            $parsedQueryString->signatureAlgorithm = $parameters[self::PARAMETER_SIGNATURE_ALGORITHM];
        }

        if ($parsedQueryString->signatureAlgorithm === null && $parsedQueryString->signature !== null) {
            throw new InvalidReceivedAuthnRequestQueryStringException(sprintf(
                'Invalid ReceivedAuthnRequest query string ("%s") contains a signature but not a signature algorithm',
                $queryString
            ));
        }
        if ($parsedQueryString->signature === null && $parsedQueryString->signatureAlgorithm !== null) {
            throw new InvalidReceivedAuthnRequestQueryStringException(sprintf(
                'Invalid ReceivedAuthnRequest query string ("%s") contains a signature algorithm but not a signature',
                $queryString
            ));
        }

        return $parsedQueryString;
    }

    /**
     * @return bool
     */
    public function hasRelayState()
    {
        return $this->relayState !== null;
    }

    /**
     * @return string
     */
    public function getSignedQueryString()
    {
        $query = self::PARAMETER_REQUEST . '=' . $this->samlRequest;

        if ($this->hasRelayState()) {
            $query .= '&' . self::PARAMETER_RELAY_STATE . '=' . $this->relayState;
        }

        if ($this->isSigned()) {
            $query .= '&' . self::PARAMETER_SIGNATURE . '=' . $this->signature
               . '&' . self::PARAMETER_SIGNATURE_ALGORITHM . '=' . $this->signatureAlgorithm;
        }

        return $query;
    }

    /**
     * @return string
     */
    public function getSignableQueryString()
    {
        if ($this->signatureAlgorithm === null) {
            throw new RuntimeException(sprintf(
                'Cannot get signable request query from received authn request query string ("%s"): SigAlg missing',
                $this->getSignedQueryString()
            ));
        }

        $query = self::PARAMETER_REQUEST . '=' . $this->samlRequest;

        if ($this->hasRelayState()) {
            $query .= '&' . self::PARAMETER_RELAY_STATE . '=' . $this->relayState;
        }

        $query .= '&' . self::PARAMETER_SIGNATURE_ALGORITHM . '=' . $this->signatureAlgorithm;

        return $query;
    }

    /**
     * @return string
     */
    public function getDecodedSamlRequest()
    {
        $samlRequest = base64_decode(urldecode($this->samlRequest), true);

        // Catch any errors gzinflate triggers
        $errorNo = $errorMessage = null;
        set_error_handler(function ($number, $message) use (&$errorNo, &$errorMessage) {
            $errorNo      = $number;
            $errorMessage = $message;
        });
        $samlRequest = gzinflate($samlRequest);
        restore_error_handler();

        if ($samlRequest === false) {
            throw new InvalidRequestException(sprintf(
                'Failed inflating SAML Request; error "%d": "%s"',
                $errorNo,
                $errorMessage
            ));
        }

        return $samlRequest;
    }

    /**
     * @return string
     */
    public function getDecodedSignature()
    {
        if (!$this->isSigned()) {
            throw new RuntimeException('Cannot decode signature: SAMLRequest is not signed');
        }

        return base64_decode(urldecode($this->signature), true);
    }

    /**
     * @return null|string
     */
    public function getSignature()
    {
        return $this->signature;
    }

    /**
     * @return bool
     */
    public function isSigned()
    {
        return $this->signature !== null && $this->signatureAlgorithm !== null;
    }

    /**
     * @return string
     */
    public function getSamlRequest()
    {
        return $this->samlRequest;
    }

    /**
     * @return null|string
     */
    public function getSignatureAlgorithm()
    {
        return $this->signatureAlgorithm;
    }

    /**
     * @return null|string
     */
    public function getRelayState()
    {
        return $this->relayState;
    }
}
