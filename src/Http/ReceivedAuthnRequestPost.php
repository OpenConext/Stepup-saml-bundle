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

use SAML2_DOMDocumentFactory;
use SAML2_Utils;
use Surfnet\SamlBundle\Exception\RuntimeException;
use Surfnet\SamlBundle\Http\Exception\InvalidReceivedAuthnRequestPostException;
use Surfnet\SamlBundle\Http\Exception\InvalidRequestException;
use Surfnet\SamlBundle\SAML2\ReceivedAuthnRequest;

final class ReceivedAuthnRequestPost implements SignatureVerifiable
{
    const PARAMETER_REQUEST = 'SAMLRequest';
    const PARAMETER_RELAY_STATE = 'RelayState';

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
     * @param array $parameters
     * @return ReceivedAuthnRequestPost
     *
     * @SuppressWarnings(PHPMD.CyclomaticComplexity) Extensive validation
     * @SuppressWarnings(PHPMD.NPathComplexity) Extensive validation
     */
    public static function parse(array $parameters)
    {
        if (base64_decode($parameters[self::PARAMETER_REQUEST], true) === false) {
            throw new InvalidRequestException('Failed decoding SAML request, did not receive a valid base64 string');
        }

        $parsed = new self($parameters[self::PARAMETER_REQUEST]);

        if (isset($parameters[self::PARAMETER_RELAY_STATE])) {
            $parsed->relayState = $parameters[self::PARAMETER_RELAY_STATE];
        }

        $decoded = $parsed->getDecodedSamlRequest();
        $request = ReceivedAuthnRequest::from($decoded);

        $signatureValue = self::extractSignatureValue($decoded);
        $request->setSignature($signatureValue);

        $parsed->signature = $request->getSignature();
        $parsed->signatureAlgorithm = $request->getSignatureMethod();

        if (!is_null($parsed->getSignature())) {
            if (is_null($parsed->getSignatureAlgorithm())) {
                throw new InvalidReceivedAuthnRequestPostException(
                    'Invalid ReceivedAuthnRequest: AuthnRequest contains a signature but not a signature algorithm'
                );
            }

            if (base64_decode($parsed->getSignature(), true) === false) {
                throw new InvalidReceivedAuthnRequestPostException(
                    'Invalid ReceivedAuthnRequest:: signature is not base64 encoded correctly'
                );
            }
            
            return $parsed;
        }

        if (!is_null($parsed->getSignatureAlgorithm())) {
            throw new InvalidReceivedAuthnRequestPostException(
                'Invalid ReceivedAuthnRequest: AuthnRequest contains a signature algorithm but not a signature'
            );
        }
        // Return unsigned AuthnRequest
        return $parsed;
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
    public function getDecodedSamlRequest()
    {
        $samlRequest = base64_decode($this->samlRequest);
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

        return base64_decode($this->signature);
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

    /**
     * @param $decodedSamlRequest
     * @return string|null
     */
    private static function extractSignatureValue($decodedSamlRequest)
    {
        // additional security against XXE Processing vulnerability
        $previous = libxml_disable_entity_loader(true);
        $document = SAML2_DOMDocumentFactory::fromString($decodedSamlRequest);
        libxml_disable_entity_loader($previous);

        $signatureValue = null;
        $signatureValueNode = SAML2_Utils::xpQuery($document->firstChild, './ds:Signature/ds:SignatureValue');
        // The signature value can't be read from the SAML2_Message
        if (!empty($signatureValueNode) && $signatureValueNode[0] instanceof \DOMElement && $signatureValueNode[0]->nodeValue) {
            $signatureValue = $signatureValueNode[0]->nodeValue;
        }
        
        return $signatureValue;
    }

    public function getSignedQueryString()
    {
        // TODO: Implement getSignedQueryString() method.
    }
}
