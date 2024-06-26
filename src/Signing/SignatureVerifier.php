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

use Exception;
use Psr\Log\LoggerInterface;
use RobRichards\XMLSecLibs\XMLSecurityKey;
use SAML2\Certificate\Key;
use SAML2\Certificate\KeyLoader;
use SAML2\Certificate\X509;
use Surfnet\SamlBundle\Entity\ServiceProvider;
use Surfnet\SamlBundle\Http\ReceivedAuthnRequestQueryString;
use Surfnet\SamlBundle\Http\SignatureVerifiable;
use Surfnet\SamlBundle\SAML2\AuthnRequest;

class SignatureVerifier
{
    public function __construct(
        private readonly KeyLoader $keyLoader,
        private readonly LoggerInterface $logger
    ) {
    }

    public function verifyIsSignedBy(SignatureVerifiable $request, ServiceProvider $serviceProvider): bool
    {
        $this->logger->debug(sprintf('Extracting public keys for ServiceProvider "%s"', $serviceProvider->getEntityId()));

        $keys = $this->keyLoader->extractPublicKeys($serviceProvider);

        $this->logger->debug(sprintf('Found "%d" keys, filtering the keys to get X509 keys', $keys->count()));
        $x509Keys = $keys->filter(fn(Key $key): bool => $key instanceof X509);

        $this->logger->debug(sprintf(
            'Found "%d" X509 keys, attempting to use each for signature verification',
            $x509Keys->count()
        ));

        foreach ($x509Keys as $key) {
            if ($this->isRequestSignedWith($request, $key)) {
                return true;
            }
        }

        $this->logger->debug('Signature could not be verified with any of the found X509 keys.');

        return false;
    }

    public function verifySignatureAlgorithmSupported(ReceivedAuthnRequestQueryString $request): bool
    {
        return $request->getSignatureAlgorithm() === XMLSecurityKey::RSA_SHA256;
    }

    public function isRequestSignedWith(SignatureVerifiable $request, X509 $publicKey): bool
    {
        $this->logger->debug(sprintf('Attempting to verify signature with certificate "%s"', $publicKey->getCertificate()));
        $key = new XMLSecurityKey(XMLSecurityKey::RSA_SHA256, ['type' => 'public']);
        $key->loadKey($publicKey->getCertificate());

        if ($request->verify($key)) {
            $this->logger->debug('Signature VERIFIED');
            return true;
        }

        $this->logger->debug('Signature NOT VERIFIED');

        return false;
    }

    public function hasValidSignature(AuthnRequest $request, ServiceProvider $serviceProvider): bool
    {
        $this->logger->debug(sprintf('Extracting public keys for ServiceProvider "%s"', $serviceProvider->getEntityId()));

        $keys = $this->keyLoader->extractPublicKeys($serviceProvider);

        $this->logger->debug(sprintf('Found "%d" keys, filtering the keys to get X509 keys', $keys->count()));
        $x509Keys = $keys->filter(fn(Key $key): bool => $key instanceof X509);

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
     * @throws Exception
     */
    public function isSignedWith(AuthnRequest $request, X509 $publicKey): bool
    {
        $this->logger->debug(sprintf('Attempting to verify signature with certificate "%s"', $publicKey->getCertificate()));
        $key = new XMLSecurityKey(XMLSecurityKey::RSA_SHA256, ['type' => 'public']);
        $key->loadKey($publicKey->getCertificate());

        $isVerified = $key->verifySignature($request->getSignedRequestQuery(), $request->getSignature());
        if ($isVerified !== 1) {
            $this->logger->debug('Signature NOT VERIFIED');
            return false;
        }

        $this->logger->debug('Signature VERIFIED');
        return true;
    }
}
