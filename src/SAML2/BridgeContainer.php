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
use Psr\Log\LoggerInterface;
use SAML2\Compat\AbstractContainer;

/**
 * Container that is required so that we can make the SAML2 lib work.
 * This container is set as the container in the SurfnetSamlBundle::boot() method
 */
class BridgeContainer extends AbstractContainer
{
    /**
     * @var \Psr\Log\LoggerInterface
     */
    private $logger;

    public function __construct(LoggerInterface $logger)
    {
        $this->logger = $logger;
    }

    /**
     * @return \Psr\Log\LoggerInterface
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

    public function debugMessage($message, string $type): void
    {
        if ($message instanceof \DOMElement) {
            $message = $message->ownerDocument->saveXML($message);
        }

        $this->logger->debug($message, ['type' => $type]);
    }

    public function redirect(string $url, array $data = []): void
    {
        throw new BadMethodCallException(sprintf(
            "%s:%s may not be called in the Surfnet\\SamlBundle as it doesn't work with Symfony2",
            __CLASS__,
            __METHOD__
        ));
    }

    public function postRedirect(string $url, array $data = []): void
    {
        throw new BadMethodCallException(sprintf(
            "%s:%s may not be called in the Surfnet\\SamlBundle as it doesn't work with Symfony2",
            __CLASS__,
            __METHOD__
        ));
    }

    /**
     * @return string
     */
    public function getTempDir() : string
    {
        return sys_get_temp_dir();
    }

    /**
     * @param string $filename
     * @param string $data
     * @param int|null $mode
     * @return void
     */
    public function writeFile(string $filename, string $data, int $mode = null) : void
    {
        if ($mode === null) {
            $mode = 0600;
        }
        file_put_contents($filename, $data);
        chmod($filename, $mode);
    }
}
