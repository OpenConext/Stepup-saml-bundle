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

namespace Surfnet\SamlBundle\Tests;

use BadMethodCallException;
use SAML2\Compat\AbstractContainer;
use Psr\Log\LoggerInterface;

class TestSaml2Container extends AbstractContainer
{
    private LoggerInterface $logger;

    public function __construct(LoggerInterface $logger = null)
    {
        $this->logger = $logger;
    }

    public function getLogger(): LoggerInterface
    {
        return $this->logger;
    }

    /**
     * Generate a random identifier for identifying SAML2 documents.
     */
    public function generateId() : string
    {
        return '1';
    }

    public function debugMessage($message, string $type) : void
    {
        $this->logger->debug($message, ['type' => $type]);
    }

    public function redirect(string $url, array $data = []) : void
    {
        throw new BadMethodCallException(
            sprintf(
                "[TEST] %s:%s may not be called in the Surfnet\\SamlBundle as it doesn't work with Symfony2",
                __CLASS__,
                __METHOD__
            )
        );
    }

    public function postRedirect(string $url, array $data = []) : void
    {
        throw new BadMethodCallException(
            sprintf(
                "[TEST] %s:%s may not be called in the Surfnet\\SamlBundle as it doesn't work with Symfony2",
                __CLASS__,
                __METHOD__
            )
        );
    }

    public function getTempDir(): string
    {
        // TODO: Implement getTempDir() method.
    }

    public function writeFile(string $filename, string $data, int $mode = null): void
    {
        // TODO: Implement writeFile() method.
    }
}
