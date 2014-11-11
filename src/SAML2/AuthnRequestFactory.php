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

use DOMDocument;
use SAML2_AuthnRequest;
use SAML2_Certificate_PrivateKeyLoader;
use SAML2_Configuration_PrivateKey;
use SAML2_Const;
use SAML2_Message;
use Surfnet\SamlBundle\Entity\IdentityProvider;
use Surfnet\SamlBundle\Entity\ServiceProvider;
use Surfnet\SamlBundle\Exception\RuntimeException;
use Symfony\Component\HttpFoundation\Request;
use XMLSecurityKey;

class AuthnRequestFactory
{
    /**
     * @param Request $httpRequest
     * @return AuthnRequest
     */
    public static function createFromHttpRequest(Request $httpRequest)
    {
        // the GET parameter is already urldecoded by Symfony, so we should not do it again.
        $samlRequest = gzinflate(base64_decode($httpRequest->get(AuthnRequest::PARAMETER_REQUEST)));

        $document = new DOMDocument();
        $document->loadXML($samlRequest);

        $request = SAML2_Message::fromXML($document->firstChild);

        if (!$request instanceof SAML2_AuthnRequest) {
            throw new RuntimeException(sprintf(
                'The received request is not an AuthnRequest, "%s" received instead',
                substr(get_class($request), strrpos($request, '_') + 1)
            ));
        }

        return AuthnRequest::create(
            $request,
            $httpRequest->get(AuthnRequest::PARAMETER_REQUEST),
            $httpRequest->get(AuthnRequest::PARAMETER_RELAY_STATE),
            $httpRequest->get(AuthnRequest::PARAMETER_SIGNATURE),
            $httpRequest->get(AuthnRequest::PARAMETER_SIGNATURE_ALGORITHM)
        );
    }

    /**
     * @param ServiceProvider  $serviceProvider
     * @param IdentityProvider $identityProvider
     * @return AuthnRequest
     */
    public static function createNewRequest(ServiceProvider $serviceProvider, IdentityProvider $identityProvider)
    {
        $request = new SAML2_AuthnRequest();
        $request->setAssertionConsumerServiceURL($serviceProvider->getAssertionConsumerUrl());
        $request->setDestination($identityProvider->getSsoUrl());
        $request->setIssuer($serviceProvider->getEntityId());
        $request->setProtocolBinding(SAML2_Const::BINDING_HTTP_POST);
        $request->setSignatureKey(self::loadPrivateKey(
            $serviceProvider->getPrivateKey(SAML2_Configuration_PrivateKey::NAME_DEFAULT)
        ));

        return AuthnRequest::createNew($request);
    }

    /**
     * @param SAML2_Configuration_PrivateKey $key
     * @return SAML2_Configuration_PrivateKey|XMLSecurityKey
     */
    private static function loadPrivateKey(SAML2_Configuration_PrivateKey $key)
    {
        $keyLoader = new SAML2_Certificate_PrivateKeyLoader();
        $privateKey = $keyLoader->loadPrivateKey($key);

        $key        = new XMLSecurityKey(XMLSecurityKey::RSA_SHA256, ['type' => 'private']);
        $key->loadKey($privateKey->getKeyAsString());

        return $key;
    }
}
