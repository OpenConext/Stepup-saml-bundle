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

namespace Surfnet\SamlBundle\Service;

use RobRichards\XMLSecLibs\XMLSecurityKey;
use SAML2\Certificate\KeyLoader as PublicKeyLoader;
use SAML2\Certificate\PrivateKey;
use SAML2\Certificate\PrivateKeyLoader;
use SAML2\Certificate\X509;
use SAML2\Configuration\PrivateKey as PrivateKeyFile;
use SAML2\Utils;
use Surfnet\SamlBundle\Signing\KeyPair;
use Surfnet\SamlBundle\Signing\Signable;

class SigningService
{
    /**
     * @var KeyLoader
     */
    private $publicKeyLoader;

    /**
     * @var PrivateKeyLoader
     */
    private $privateKeyLoader;

    /**
     * @param PublicKeyLoader  $publicKeyLoader
     * @param PrivateKeyLoader $privateKeyLoader
     */
    public function __construct(PublicKeyLoader $publicKeyLoader, PrivateKeyLoader $privateKeyLoader)
    {
        $this->publicKeyLoader = $publicKeyLoader;
        $this->privateKeyLoader = $privateKeyLoader;
    }

    /**
     * @param Signable $signable
     * @param KeyPair  $keyPair
     * @return \DOMDocument
     * @throws \Exception
     */
    public function sign(Signable $signable, KeyPair $keyPair)
    {
        $publicKey = $this->loadPublicKeyFromFile($keyPair->publicKeyFile);
        $privateKey = $this->loadPrivateKeyFromFile($keyPair->privateKeyFile);

        $key = new XMLSecurityKey(XMLSecurityKey::RSA_SHA256, ['type' => 'private']);
        $key->loadKey($privateKey->getKeyAsString());

        Utils::insertSignature(
            $key,
            [$publicKey->getCertificate()],
            $signable->getRootDomElement(),
            $signable->getAppendBeforeNode()
        );

        return $signable;
    }

    /**
     * @param  string $publicKeyFile /full/path/to/the/public/key
     * @return X509
     */
    public function loadPublicKeyFromFile($publicKeyFile)
    {
        $this->publicKeyLoader->loadCertificateFile($publicKeyFile);
        $keyCollection = $this->publicKeyLoader->getKeys();
        $publicKey = $keyCollection->getOnlyElement();

        // remove it from the collection so we can reuse the publicKeyLoader for consecutive signing
        $keyCollection->remove($publicKey);

        return $publicKey;
    }

    /**
     * @param  string $privateKeyFile /full/path/to/the/private/key
     * @return PrivateKey
     */
    public function loadPrivateKeyFromFile($privateKeyFile)
    {
        $privateKey = new PrivateKeyFile($privateKeyFile, 'metadata');
        return $this->privateKeyLoader->loadPrivateKey($privateKey);
    }
}
