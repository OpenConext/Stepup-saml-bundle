<?php

/**
 * Copyright 2014 SURFnet bv
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

namespace Surfnet\SamlBundle\SAML2;

use SAML2_AuthnRequest;

class AuthnRequest
{
    const PARAMETER_RELAY_STATE = 'RelayState';
    const PARAMETER_REQUEST = 'SAMLRequest';
    const PARAMETER_SIGNATURE = 'Signature';
    const PARAMETER_SIGNATURE_ALGORITHM = 'SigAlg';

    /**
     * @var string the raw request as sent
     */
    private $rawRequest;

    /**
     * @var SAML2_AuthnRequest
     */
    private $request;

    /**
     * @var string
     */
    private $signature;

    /**
     * @var string
     */
    private $signatureAlgorithm;

    /**
     * @param SAML2_AuthnRequest $request
     */
    private function __construct(SAML2_AuthnRequest $request)
    {
        $this->request = $request;
    }

    /**
     * @param SAML2_AuthnRequest $request
     * @param string             $rawRequest
     * @param string             $relayState
     * @param string             $signature
     * @param string             $signatureAlgorithm
     * @return AuthnRequest
     */
    public static function create(
        SAML2_AuthnRequest $request,
        $rawRequest,
        $relayState,
        $signature,
        $signatureAlgorithm
    ) {
        $authnRequest = new self($request);
        $authnRequest->rawRequest = $rawRequest;
        if ($relayState) {
            $authnRequest->request->setRelayState($relayState);
        }
        $authnRequest->signature          = base64_decode($signature);
        $authnRequest->signatureAlgorithm = $signatureAlgorithm;

        return $authnRequest;
    }

    public static function createNew(SAML2_AuthnRequest $req)
    {
        return new self($req);
    }

    /**
     * @param array $requestedAuthnClassRef
     * @deprecated Use SAML2_AuthnRequest::setAuthenticationContext()
     */
    public function setRequestedAuthenticationContext(array $requestedAuthnClassRef)
    {
        $authnContext = ['AuthnContextClassRef' => $requestedAuthnClassRef];
        $this->request->setRequestedAuthnContext($authnContext);
    }

    /**
     * @return string|null
     */
    public function getRequestedAuthenticationContext()
    {
        $authnContext = $this->request->getRequestedAuthnContext();
        if (!is_array($authnContext) || !array_key_exists('AuthnContextClassRef', $authnContext)) {
            return null;
        }

        return reset($authnContext['AuthnContextClassRef']) ?: null;
    }

    /**
     * @param array $requestedAuthnClassRef
     */
    public function setAuthenticationContext(array $requestedAuthnClassRef)
    {
        $authnContext = ['AuthnContextClassRef' => $requestedAuthnClassRef];
        $this->request->setRequestedAuthnContext($authnContext);
    }

    /**
     * @return array
     */
    public function getAuthenticationContext()
    {
        return $this->request->getRequestedAuthnContext()['AuthnContextClassRef'];
    }

    /**
     * @return string
     */
    public function getRequestId()
    {
        return $this->request->getId();
    }

    /**
     * @return bool
     */
    public function isSigned()
    {
        return isset($this->signature);
    }

    /**
     * @return string
     */
    public function getDestination()
    {
        return $this->request->getDestination();
    }

    /**
     * @return string
     */
    public function getServiceProvider()
    {
        return $this->request->getIssuer();
    }

    /**
     * @return null|string
     */
    public function getSignature()
    {
        return $this->signature;
    }

    /**
     * @return string
     */
    public function getSignatureAlgorithm()
    {
        return $this->signatureAlgorithm;
    }

    /**
     * @return string
     */
    public function getUnsignedXML()
    {
        return $this->request->toUnsignedXML()->ownerDocument->saveXML();
    }

    /**
     * @param array $requesterIds
     * @param int   $proxyCount
     */
    public function setScoping(array $requesterIds, $proxyCount = 10)
    {
        $this->request->setRequesterID($requesterIds);
        $this->request->setProxyCount($proxyCount);
    }

    /**
     * @return string
     */
    public function buildRequestQuery()
    {
        $requestAsXml = $this->getUnsignedXML();
        $encodedRequest = base64_encode(gzdeflate($requestAsXml));
        $queryParams = [self::PARAMETER_REQUEST => $encodedRequest];

        if ($this->request->getRelayState() !== null) {
            $queryParams[self::PARAMETER_RELAY_STATE] = $this->request->getRelayState();
        }

        return $this->signRequestQuery($queryParams);
    }

    /**
     * @return string
     */
    public function getSignedRequestQuery()
    {
        $queryParams = [self::PARAMETER_REQUEST => $this->rawRequest];

        if ($this->request->getRelayState()) {
            $queryParams[self::PARAMETER_RELAY_STATE] = $this->request->getRelayState();
        }

        $queryParams[self::PARAMETER_SIGNATURE_ALGORITHM] = $this->signatureAlgorithm;

        return http_build_query($queryParams);
    }

    /**
     * @param array $queryParams
     * @return string
     */
    private function signRequestQuery(array $queryParams)
    {
        /** @var \XMLSecurityKey $securityKey */
        $securityKey = $this->request->getSignatureKey();
        $queryParams[self::PARAMETER_SIGNATURE_ALGORITHM] = $securityKey->type;

        $toSign = http_build_query($queryParams);
        $signature = $securityKey->signData($toSign);

        $signedQuery = $toSign . '&Signature=' . urlencode(base64_encode($signature));

        return $signedQuery;
    }
}
