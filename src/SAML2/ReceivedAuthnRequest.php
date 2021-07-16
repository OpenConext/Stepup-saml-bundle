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

namespace Surfnet\SamlBundle\SAML2;

use RobRichards\XMLSecLibs\XMLSecurityKey;
use SAML2\AuthnRequest as SAML2AuthnRequest;
use SAML2\Constants;
use SAML2\DOMDocumentFactory;
use SAML2\Message;
use Surfnet\SamlBundle\Exception\InvalidArgumentException;
use Surfnet\SamlBundle\Exception\RuntimeException;
use Surfnet\SamlBundle\SAML2\Extensions\ExtensionsMapperTrait;

final class ReceivedAuthnRequest
{
    use ExtensionsMapperTrait;

    /**
     * @var SAML2AuthnRequest
     */
    private $request;

    private function __construct(SAML2AuthnRequest $request)
    {
        $this->request = $request;
        $this->loadExtensionsFromSaml2AuthNRequest();
    }

    /**
     * @param string $decodedSamlRequest
     * @return ReceivedAuthnRequest
     */
    public static function from($decodedSamlRequest)
    {
        if (!is_string($decodedSamlRequest) || empty($decodedSamlRequest)) {
            throw new InvalidArgumentException(sprintf(
                'Could not create ReceivedAuthnRequest: expected a non-empty string, received %s',
                is_object($decodedSamlRequest) ? get_class($decodedSamlRequest) : ($decodedSamlRequest)
            ));
        }

        // additional security against XXE Processing vulnerability
        $previous = libxml_disable_entity_loader(true);
        $document = DOMDocumentFactory::fromString($decodedSamlRequest);
        libxml_disable_entity_loader($previous);

        $authnRequest = Message::fromXML($document->firstChild);

        if (!$authnRequest instanceof SAML2AuthnRequest) {
            throw new RuntimeException(sprintf(
                'The received request is not an AuthnRequest, "%s" received instead',
                substr(get_class($authnRequest), strrpos($authnRequest, '_') + 1)
            ));
        }

        return new self($authnRequest);
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
        $nameId = $this->request->getNameId();
        if (!$nameId) {
            return null;
        }

        return $nameId->value;
    }

    /**
     * @return string|null
     */
    public function getNameIdFormat()
    {
        $nameId = $this->request->getNameId();
        if (!$nameId) {
            return null;
        }

        return $nameId->Format;
    }

    /**
     * @param string      $nameId
     * @param string|null $format
     */
    public function setSubject($nameId, $format = null)
    {
        if (!is_string($nameId)) {
            throw InvalidArgumentException::invalidType('string', 'nameId', $nameId);
        }

        if (!is_null($format) && !is_string($format)) {
            throw InvalidArgumentException::invalidType('string', 'format', $format);
        }

        $nameId = [
            'Value' => $nameId,
            'Format' => ($format ?: Constants::NAMEID_UNSPECIFIED)
        ];

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

    /**
     * @return bool
     */
    public function isForceAuthn()
    {
        return $this->request->getForceAuthn();
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
     * @return string
     */
    public function getUnsignedXML()
    {
        return $this->request->toUnsignedXML()->ownerDocument->saveXML();
    }

    /**
     * @return string
     */
    public function getAssertionConsumerServiceURL()
    {
        return $this->request->getAssertionConsumerServiceURL();
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
     * @return string[]
     */
    public function getScopingRequesterIds()
    {
        return $this->request->getRequesterID();
    }

    /**
     * @param XMLSecurityKey $key
     * @return bool
     * @throws \Exception when signature is invalid (@see SAML2\Utils::validateSignature)
     */
    public function verify(XMLSecurityKey $key)
    {
        return $this->request->validate($key);
    }
}
