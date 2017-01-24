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

namespace Surfnet\SamlBundle\Signing;

use Psr\Log\LoggerInterface;
use SAML2_Certificate_Key;
use SAML2_Certificate_KeyLoader as KeyLoader;
use SAML2_Certificate_X509;
use Surfnet\SamlBundle\Entity\ServiceProvider;
use Surfnet\SamlBundle\Http\ReceivedAuthnRequestQueryString;
use Surfnet\SamlBundle\SAML2\AuthnRequest;
use XMLSecurityKey;

class SignatureVerifier
{
    /**
     * @var \SAML2_Certificate_KeyLoader
     */
    private $keyLoader;

    /**
     * @var LoggerInterface
     */
    private $logger;

    /**
     * @param KeyLoader       $keyLoader
     * @param LoggerInterface $logger
     */
    public function __construct(KeyLoader $keyLoader, LoggerInterface $logger)
    {
        $this->keyLoader = $keyLoader;
        $this->logger = $logger;
    }

    public function verifyIsSignedBy(ReceivedAuthnRequestQueryString $query, ServiceProvider $serviceProvider)
    {
        $this->logger->debug(sprintf('Extracting public keys for ServiceProvider "%s"', $serviceProvider->getEntityId()));

        $keys = $this->keyLoader->extractPublicKeys($serviceProvider);

        $this->logger->debug(sprintf('Found "%d" keys, filtering the keys to get X509 keys', $keys->count()));
        $x509Keys = $keys->filter(function (SAML2_Certificate_Key $key) {
            return $key instanceof SAML2_Certificate_X509;
        });

        $this->logger->debug(sprintf(
            'Found "%d" X509 keys, attempting to use each for signature verification',
            $x509Keys->count()
        ));

        foreach ($x509Keys as $key) {
            if ($this->isQuerySignedWith($query, $key)) {
                return true;
            }
        }

        $this->logger->debug('Signature could not be verified with any of the found X509 keys.');

        return false;
    }

    /**
     * @param ReceivedAuthnRequestQueryString $query
     * @param SAML2_Certificate_X509 $publicKey
     * @return bool
     */
    public function isQuerySignedWith(ReceivedAuthnRequestQueryString $query, SAML2_Certificate_X509 $publicKey)
    {
        $this->logger->debug(sprintf('Attempting to verify signature with certificate "%s"', $publicKey->getCertificate()));
        $key = new XMLSecurityKey(XMLSecurityKey::RSA_SHA256, array('type' => 'public'));
        $key->loadKey($publicKey->getCertificate());

        if ($key->verifySignature($query->getSignedQueryString(), $query->getDecodedSignature())) {
            $this->logger->debug('Signature VERIFIED');
            return true;
        }

        $this->logger->debug('Signature NOT VERIFIED');

        return false;
    }

    /**
     * @param AuthnRequest    $request
     * @param ServiceProvider $serviceProvider
     * @return bool
     */
    public function hasValidSignature(AuthnRequest $request, ServiceProvider $serviceProvider)
    {
        $this->logger->debug(sprintf('Extracting public keys for ServiceProvider "%s"', $serviceProvider->getEntityId()));

        $keys = $this->keyLoader->extractPublicKeys($serviceProvider);

        $this->logger->debug(sprintf('Found "%d" keys, filtering the keys to get X509 keys', $keys->count()));
        $x509Keys = $keys->filter(function (SAML2_Certificate_Key $key) {
            return $key instanceof SAML2_Certificate_X509;
        });

        $this->logger->debug(sprintf(
            'Found "%d" X509 keys, attempting to use each for signature verification',
            $x509Keys->count()
        ));

        foreach ($x509Keys as $key) {
            if ($this->isSignedWith($request, $key)) {
                return true;
            }
        }

        $this->logger->debug('Signature could not be verified with any of the found X509 keys.');

        return false;
    }

    /**
     * @param AuthnRequest           $request
     * @param SAML2_Certificate_X509 $publicKey
     * @return bool
     * @throws \Exception
     */
    public function isSignedWith(AuthnRequest $request, SAML2_Certificate_X509 $publicKey)
    {
        $this->logger->debug(sprintf('Attempting to verify signature with certificate "%s"', $publicKey->getCertificate()));
        $key = new XMLSecurityKey(XMLSecurityKey::RSA_SHA256, array('type' => 'public'));
        $key->loadKey($publicKey->getCertificate());

        if ($key->verifySignature($request->getSignedRequestQuery(), $request->getSignature())) {
            $this->logger->debug('Signature VERIFIED');
            return true;
        }

        $this->logger->debug('Signature NOT VERIFIED');

        return false;
    }
}
