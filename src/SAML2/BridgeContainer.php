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

use BadMethodCallException;
use DOMElement;
use Psr\Log\LoggerInterface;
use SAML2\Compat\AbstractContainer;

/**
 * Container that is required so that we can make the SAML2 lib work.
 * This container is set as the container in the SurfnetSamlBundle::boot() method
 */
class BridgeContainer extends AbstractContainer
{
    public function __construct(private readonly LoggerInterface $logger)
    {
    }

    /**
     * @return LoggerInterface
     */
    public function getLogger(): LoggerInterface
    {
        return $this->logger;
    }

    /**
     * Generate a random identifier for identifying SAML2 documents.
     */
    public function generateId(): string
    {
        return '_' . bin2hex(openssl_random_pseudo_bytes(30));
    }

    public function debugMessage($message, $type): void
    {
        if ($message instanceof DOMElement) {
            $message = $message->ownerDocument->saveXML($message);
        }

        $this->logger->debug($message, ['type' => $type]);
    }

    public function redirect($url, $data = []): void
    {
        $this->notSupported(__METHOD__);
    }

    public function postRedirect($url, $data = []): void
    {
        $this->notSupported(__METHOD__);
    }

    /** @throws BadMethodCallException */
    public function getTempDir(): string
    {
        $this->notSupported(__METHOD__);
        return '';
    }

    public function writeFile(string $filename, string $data, ?int $mode = null): void
    {
        $this->notSupported(__METHOD__);
    }

    public function notSupported(string $method): void
    {
        throw new BadMethodCallException(sprintf(
            "%s:%s may not be called in the Surfnet\\SamlBundle",
            self::class,
            $method
        ));
    }
}
