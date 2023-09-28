<?php declare(strict_types=1);

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

namespace Surfnet\SamlBundle\SAML2;

use RobRichards\XMLSecLibs\XMLSecurityKey;
use SAML2\AuthnRequest as SAML2AuthnRequest;
use SAML2\Constants;
use SAML2\DOMDocumentFactory;
use SAML2\Message;
use SAML2\XML\saml\NameID;
use Surfnet\SamlBundle\Exception\InvalidArgumentException;
use Surfnet\SamlBundle\Exception\RuntimeException;
use Surfnet\SamlBundle\SAML2\Extensions\ExtensionsMapperTrait;

final class ReceivedAuthnRequest
{
    use ExtensionsMapperTrait;

    private readonly SAML2AuthnRequest $request;

    private function __construct(SAML2AuthnRequest $request)
    {
        $this->request = $request;
        $this->loadExtensionsFromSaml2AuthNRequest();
    }

    public static function from(string $decodedSamlRequest): ReceivedAuthnRequest
    {
        if (!is_string($decodedSamlRequest) || $decodedSamlRequest === '') {
            throw new InvalidArgumentException(sprintf(
                'Could not create ReceivedAuthnRequest: expected a non-empty string, received %s',
                is_object($decodedSamlRequest) ? $decodedSamlRequest::class : ($decodedSamlRequest)
            ));
        }

        // additional security against XXE Processing vulnerability
        $document = DOMDocumentFactory::fromString($decodedSamlRequest);

        $authnRequest = Message::fromXML($document->firstChild);

        if (!$authnRequest instanceof SAML2AuthnRequest) {
            throw new RuntimeException(sprintf(
                'The received request is not an AuthnRequest, "%s" received instead',
                $authnRequest::class
            ));
        }

        return new self($authnRequest);
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
        if (!$nameId instanceof \SAML2\XML\saml\NameID) {
            return null;
        }

        return $nameId->getValue();
    }

    public function getNameIdFormat(): ?string
    {
        $nameId = $this->request->getNameId();
        if (!$nameId instanceof \SAML2\XML\saml\NameID) {
            return null;
        }

        return $nameId->getFormat();
    }

    public function setSubject(string $nameId, ?string $format = null): void
    {
        $nameIdVo = new NameID;
        $nameIdVo->setValue($nameId);
        $nameIdVo->setFormat(($format ?: Constants::NAMEID_UNSPECIFIED));

        $this->request->setNameId($nameId);
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

    public function getDestination(): ?string
    {
        return $this->request->getDestination();
    }

    public function getServiceProvider(): ?string
    {
        if (!$this->request->getIssuer() instanceof \SAML2\XML\saml\Issuer) {
            return null;
        }
        return $this->request->getIssuer()->getValue();
    }

    public function getUnsignedXML(): string
    {
        return $this->request->toUnsignedXML()->ownerDocument->saveXML();
    }

    public function getAssertionConsumerServiceURL(): string
    {
        return $this->request->getAssertionConsumerServiceURL();
    }

    public function setScoping(array $requesterIds, int $proxyCount = 10): void
    {
        $this->request->setRequesterID($requesterIds);
        $this->request->setProxyCount($proxyCount);
    }

    public function getScopingRequesterIds(): array
    {
        return $this->request->getRequesterID();
    }

    /**
     * @throws \Exception when signature is invalid (@see SAML2\Utils::validateSignature)
     */
    public function verify(XMLSecurityKey $key): bool
    {
        return $this->request->validate($key);
    }
}
