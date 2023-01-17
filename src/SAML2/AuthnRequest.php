<?php declare(strict_types=1);

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

use SAML2\AuthnRequest as SAML2AuthnRequest;
use SAML2\Constants;
use SAML2\XML\saml\NameID;
use Surfnet\SamlBundle\SAML2\Extensions\ExtensionsMapperTrait;

class AuthnRequest
{
    use ExtensionsMapperTrait;

    const PARAMETER_RELAY_STATE = 'RelayState';
    const PARAMETER_REQUEST = 'SAMLRequest';
    const PARAMETER_SIGNATURE = 'Signature';
    const PARAMETER_SIGNATURE_ALGORITHM = 'SigAlg';

    private ?string $rawRequest;

    private SAML2AuthnRequest $request;

    private ?string $signature;

    private ?string $signatureAlgorithm;

    private function __construct(SAML2AuthnRequest $request)
    {
        $this->request = $request;
        $this->loadExtensionsFromSaml2AuthNRequest();
    }

    /**
     * @deprecated use ReceivedAuthnRequest::from()
     */
    public static function createUnsigned(
        SAML2AuthnRequest $request,
        string $rawRequest,
        string $relayState
    ): self {
        $authnRequest = new self($request);
        $authnRequest->rawRequest = $rawRequest;
        if ($relayState) {
            $authnRequest->request->setRelayState($relayState);
        }

        return $authnRequest;
    }

    /**
     * @deprecated use ReceivedAuthnRequest::from()
     */
    public static function createSigned(
        SAML2AuthnRequest $request,
        string $rawRequest,
        ?string $relayState,
        string $signature,
        string $signatureAlgorithm
    ): self {
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
     */
    public static function create(
        SAML2AuthnRequest $request,
        string $rawRequest,
        ?string $relayState,
        string $signature,
        string $signatureAlgorithm
    ): self {
        return static::createSigned(
            $request,
            $rawRequest,
            $relayState,
            $signature,
            $signatureAlgorithm
        );
    }

    public static function createNew(SAML2AuthnRequest $req): self
    {
        return new self($req);
    }

    public function getAuthenticationContextClassRef(): ?string
    {
        $authnContext = $this->request->getRequestedAuthnContext();

        if (!is_array($authnContext) || !array_key_exists('AuthnContextClassRef', $authnContext)) {
            return null;
        }

        return reset($authnContext['AuthnContextClassRef']) ?: null;
    }

    public function setAuthenticationContextClassRef($authnClassRef): void
    {
        $authnContext = ['AuthnContextClassRef' => [$authnClassRef]];
        $this->request->setRequestedAuthnContext($authnContext);
    }

    public function getNameId(): ?string
    {
        $nameId = $this->request->getNameId();

        if (!$nameId->getValue()) {
            return null;
        }

        return $nameId->getValue();
    }

    public function getNameIdFormat(): ?string
    {
        $nameId = $this->request->getNameId();

        if (!$nameId->getFormat()) {
            return null;
        }

        return $nameId->getFormat();
    }

    public function setSubject(string $nameId, ?string $format = null): void
    {
        $nameIdVo = new NameID;
        $nameIdVo->setValue($nameId);
        $nameIdVo->setFormat(($format ?: Constants::NAMEID_UNSPECIFIED));

        $this->request->setNameId($nameIdVo);
    }

    public function getRequestId(): string
    {
        return $this->request->getId();
    }

    public function isPassive(): bool
    {
        return $this->request->getIsPassive();
    }

    public function isForceAuthn(): bool
    {
        return $this->request->getForceAuthn();
    }

    public function isSigned(): bool
    {
        return !empty($this->signature);
    }

    public function getAssertionConsumerServiceURL(): ?string
    {
        return $this->request->getAssertionConsumerServiceURL();
    }

    public function getDestination(): string
    {
        return $this->request->getDestination();
    }

    /**
     * @return string
     */
    public function getServiceProvider(): string
    {
        return $this->request->getIssuer()->getValue();
    }

    /**
     * @return null|string
     */
    public function getSignature(): ?string
    {
        return $this->signature;
    }

    public function getSignatureAlgorithm(): string
    {
        return $this->signatureAlgorithm;
    }

    public function getUnsignedXML(): string
    {
        return $this->request->toUnsignedXML()->ownerDocument->saveXML();
    }

    public function setScoping(array $requesterIds, int $proxyCount = 10): void
    {
        $this->request->setRequesterID($requesterIds);
        $this->request->setProxyCount($proxyCount);
    }

    public function buildRequestQuery(): string
    {
        $requestAsXml = $this->getUnsignedXML();
        $encodedRequest = base64_encode(gzdeflate($requestAsXml));
        $queryParams = [self::PARAMETER_REQUEST => $encodedRequest];

        if ($this->request->getRelayState() !== null) {
            $queryParams[self::PARAMETER_RELAY_STATE] = $this->request->getRelayState();
        }

        return $this->signRequestQuery($queryParams);
    }

    public function getSignedRequestQuery(): string
    {
        $queryParams = [self::PARAMETER_REQUEST => $this->rawRequest];

        if ($this->request->getRelayState()) {
            $queryParams[self::PARAMETER_RELAY_STATE] = $this->request->getRelayState();
        }

        $queryParams[self::PARAMETER_SIGNATURE_ALGORITHM] = $this->signatureAlgorithm;

        return http_build_query($queryParams);
    }

    private function signRequestQuery(array $queryParams): string
    {
        $securityKey = $this->request->getSignatureKey();
        $queryParams[self::PARAMETER_SIGNATURE_ALGORITHM] = $securityKey->type;

        $toSign = http_build_query($queryParams);
        $signature = $securityKey->signData($toSign);

        $signedQuery = $toSign . '&Signature=' . urlencode(base64_encode($signature));

        return $signedQuery;
    }
}
