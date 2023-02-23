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

use RobRichards\XMLSecLibs\XMLSecurityKey;
use SAML2\AuthnRequest as SAML2AuthnRequest;
use SAML2\Certificate\PrivateKeyLoader;
use SAML2\Configuration\PrivateKey;
use SAML2\Constants;
use SAML2\DOMDocumentFactory;
use SAML2\Message;
use SAML2\XML\saml\Issuer;
use Surfnet\SamlBundle\Entity\IdentityProvider;
use Surfnet\SamlBundle\Entity\ServiceProvider;
use Surfnet\SamlBundle\Exception\RuntimeException;
use Surfnet\SamlBundle\Http\Exception\InvalidRequestException;
use Symfony\Component\HttpFoundation\Request;

/**
 * @SuppressWarnings(PHPMD.CouplingBetweenObjects)
 */
class AuthnRequestFactory
{
    public static function createUnsignedFromHttpRequest(Request $httpRequest): AuthnRequest
    {
        return AuthnRequest::createUnsigned(
            self::createAuthnRequestFromHttpRequest($httpRequest),
            $httpRequest->get(AuthnRequest::PARAMETER_REQUEST),
            $httpRequest->get(AuthnRequest::PARAMETER_RELAY_STATE)
        );
    }

    /**
     * @deprecated use ReceivedAuthnRequest::from()
     */
    public static function createSignedFromHttpRequest(Request $httpRequest): AuthnRequest
    {
        return AuthnRequest::createSigned(
            self::createAuthnRequestFromHttpRequest($httpRequest),
            $httpRequest->get(AuthnRequest::PARAMETER_REQUEST),
            $httpRequest->get(AuthnRequest::PARAMETER_RELAY_STATE),
            $httpRequest->get(AuthnRequest::PARAMETER_SIGNATURE),
            $httpRequest->get(AuthnRequest::PARAMETER_SIGNATURE_ALGORITHM)
        );
    }

    /**
     * @deprecated use createSignedFromHttpRequest or createUnsignedFromHttpRequest
     */
    public static function createFromHttpRequest(Request $httpRequest): AuthnRequest
    {
        return static::createSignedFromHttpRequest($httpRequest);
    }

    /**
     * @throws \Exception
     */
    private static function createAuthnRequestFromHttpRequest(
        Request $httpRequest
    ): SAML2AuthnRequest {
        // the GET parameter is already urldecoded by Symfony, so we should not do it again.
        $samlRequest = base64_decode($httpRequest->get(AuthnRequest::PARAMETER_REQUEST), true);
        if ($samlRequest === false) {
            throw new InvalidRequestException('Failed decoding the request, did not receive a valid base64 string');
        }

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
                'Failed inflating the request; error "%d": "%s"',
                $errorNo,
                $errorMessage
            ));
        }

        // additional security against XXE Processing vulnerability
        $document = DOMDocumentFactory::fromString($samlRequest);

        $request = Message::fromXML($document->firstChild);

        if (!$request instanceof SAML2AuthnRequest) {
            throw new RuntimeException(sprintf(
                'The received request is not an AuthnRequest, "%s" received instead',
                get_class($request)
            ));
        }

        return $request;
    }

    public static function createNewRequest(
        ServiceProvider $serviceProvider,
        IdentityProvider $identityProvider,
        bool $forceAuthn = false
    ): AuthnRequest {
        $issuer = new Issuer();
        $issuer->setValue($serviceProvider->getEntityId());
        $request = new SAML2AuthnRequest();
        $request->setAssertionConsumerServiceURL($serviceProvider->getAssertionConsumerUrl());
        $request->setDestination($identityProvider->getSsoUrl());
        $request->setIssuer($issuer);
        $request->setProtocolBinding(Constants::BINDING_HTTP_POST);
        $request->setForceAuthn($forceAuthn);
        $request->setSignatureKey(self::loadPrivateKey(
            $serviceProvider->getPrivateKey(PrivateKey::NAME_DEFAULT)
        ));

        return AuthnRequest::createNew($request);
    }

    private static function loadPrivateKey(PrivateKey $key): XMLSecurityKey
    {
        $keyLoader = new PrivateKeyLoader();
        $privateKey = $keyLoader->loadPrivateKey($key);

        $key        = new XMLSecurityKey(XMLSecurityKey::RSA_SHA256, ['type' => 'private']);
        $key->loadKey($privateKey->getKeyAsString());

        return $key;
    }
}
