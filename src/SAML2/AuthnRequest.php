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

use RobRichards\XMLSecLibs\XMLSecurityKey;
use SAML2\AuthnRequest as SAML2AuthnRequest;
use SAML2\Constants;
use SAML2\XML\saml\NameID;
use Surfnet\SamlBundle\Exception\InvalidArgumentException;
use Surfnet\SamlBundle\SAML2\Extensions\ExtensionsMapperTrait;

class AuthnRequest
{
    use ExtensionsMapperTrait;

    const PARAMETER_RELAY_STATE = 'RelayState';
    const PARAMETER_REQUEST = 'SAMLRequest';
    const PARAMETER_SIGNATURE = 'Signature';
    const PARAMETER_SIGNATURE_ALGORITHM = 'SigAlg';

    /**
     * @var string|null the raw request as sent
     */
    private $rawRequest;

    /**
     * @var SAML2AuthnRequest
     */
    private $request;

    /**
     * @var null|string
     */
    private $signature;

    /**
     * @var null|string
     */
    private $signatureAlgorithm;

    /**
     * @param SAML2AuthnRequest $request
     */
    private function __construct(SAML2AuthnRequest $request)
    {
        $this->request = $request;
        $this->loadExtensionsFromSaml2AuthNRequest();
    }

    /**
     * @deprecated use ReceivedAuthnRequest::from()
     * @param SAML2AuthnRequest $request
     * @param string $rawRequest
     * @param string $relayState
     * @return AuthnRequest
     */
    public static function createUnsigned(
        SAML2AuthnRequest $request,
        $rawRequest,
        $relayState
    ) {
        $authnRequest = new self($request);
        $authnRequest->rawRequest = $rawRequest;
        if ($relayState) {
            $authnRequest->request->setRelayState($relayState);
        }

        return $authnRequest;
    }

    /**
     * @deprecated use ReceivedAuthnRequest::from()
     * @param SAML2AuthnRequest $request
     * @param string $rawRequest
     * @param string $relayState
     * @param string $signature
     * @param string $signatureAlgorithm
     * @return AuthnRequest
     */
    public static function createSigned(
        SAML2AuthnRequest $request,
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
        $authnRequest->signature = base64_decode($signature, true);
        $authnRequest->signatureAlgorithm = $signatureAlgorithm;

        return $authnRequest;
    }

    /**
     * @deprecated use ReceivedAuthnRequest::from()
     * @param SAML2AuthnRequest $request
     * @param string $rawRequest
     * @param string $relayState
     * @param string $signature
     * @param string $signatureAlgorithm
     * @return AuthnRequest
     */
    public static function create(
        SAML2AuthnRequest $request,
        $rawRequest,
        $relayState,
        $signature,
        $signatureAlgorithm
    ) {
        return static::createSigned(
            $request,
            $rawRequest,
            $relayState,
            $signature,
            $signatureAlgorithm
        );
    }

    public static function createNew(SAML2AuthnRequest $req)
    {
        return new self($req);
    }

    /**
     * @return string|null
     */
    public function getAuthenticationContextClassRef()
    {
        $authnContext = $this->request->getRequestedAuthnContext();

        if (!is_array($authnContext) || !array_key_exists('AuthnContextClassRef', $authnContext)) {
            return null;
        }

        return reset($authnContext['AuthnContextClassRef']) ?: null;
    }

    /**
     * @param string $authnClassRef
     */
    public function setAuthenticationContextClassRef($authnClassRef)
    {
        $authnContext = ['AuthnContextClassRef' => [$authnClassRef]];
        $this->request->setRequestedAuthnContext($authnContext);
    }

    /**
     * @return string|null
     */
    public function getNameId()
    {
        $nameid=$this->request->getNameId();
        if (null == $nameid) {
            return null;
        }
        return $nameid->getValue();
    }

    /**
     * @return string|null
     */
    public function getNameIdFormat()
    {
        $nameid=$this->request->getNameId();
        if (null == $nameid) {
            return null;
        }
        return $nameid->getFormat();
    }

    /**
     * @param string      $nameIdValue
     * @param string|null $format
     */
    public function setSubject($nameIdValue, $format = null)
    {
        if (!is_string($nameIdValue)) {
            throw InvalidArgumentException::invalidType('string', 'nameId', $nameIdValue);
        }

        if (!is_null($format) && !is_string($format)) {
            throw InvalidArgumentException::invalidType('string', 'format', $format);
        }


        $nameId = new NameID();
        $nameId->setValue($nameIdValue);
        $nameId->setFormat($format ?: Constants::NAMEID_UNSPECIFIED);

        $this->request->setNameId($nameId);
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
    public function isPassive()
    {
        return $this->request->getIsPassive();
    }

    public function isForceAuthn(): bool
    {
        return $this->request->getForceAuthn();
    }

    public function setForceAuthn(bool $isForceAuthN): void
    {
        $this->request->setForceAuthn($isForceAuthN);
    }

    /**
     * @return bool
     */
    public function isSigned()
    {
        return !empty($this->signature);
    }

    /**
     * @return null|string
     */
    public function getAssertionConsumerServiceURL()
    {
        return $this->request->getAssertionConsumerServiceURL();
    }

    /**
     * @return string
     */
    public function getDestination()
    {
        return $this->request->getDestination();
    }

    public function getServiceProvider(): string
    {
        return $this->request->getIssuer()->getValue();
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
        /** @var XMLSecurityKey $securityKey */
        $securityKey = $this->request->getSignatureKey();
        $queryParams[self::PARAMETER_SIGNATURE_ALGORITHM] = $securityKey->type;

        $toSign = http_build_query($queryParams);
        $signature = $securityKey->signData($toSign);

        $signedQuery = $toSign . '&Signature=' . urlencode(base64_encode($signature));

        return $signedQuery;
    }
}
