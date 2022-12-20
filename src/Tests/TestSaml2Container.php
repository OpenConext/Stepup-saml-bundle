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

namespace Surfnet\SamlBundle\Tests;

use BadMethodCallException;
use Psr\Log\LoggerInterface;
use SAML2\Compat\AbstractContainer;

use function chmod;
use function file_get_contents;
use function sprintf;
use function sys_get_temp_dir;

class TestSaml2Container extends AbstractContainer
{
    /** @var \Psr\Log\LoggerInterface */
    private $logger;


    /**
     * Get a PSR-3 compatible logger.
     * @return \Psr\Log\LoggerInterface
     */
    public function __construct(LoggerInterface $logger = null)
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
     * @return string
     */
    public function generateId(): string
    {
        return '1';
    }


    /**
     * Log an incoming message to the debug log.
     *
     * Type can be either:
     * - **in** XML received from third party
     * - **out** XML that will be sent to third party
     * - **encrypt** XML that is about to be encrypted
     * - **decrypt** XML that was just decrypted
     *
     * @param \DOMElement|string $message
     * @param string $type
     * @return void
     */
    public function debugMessage($message, string $type): void
    {
        $this->logger->debug($message, ['type' => $type]);
    }


    /**
     * Trigger the user to perform a GET to the given URL with the given data.
     *
     * @param string $url
     * @param array $data
     * @return void
     */
    public function redirect(string $url, array $data = []): void
    {
        throw new BadMethodCallException(sprintf(
            "[TEST] %s:%s may not be called in the Surfnet\\SamlBundle as it doesn't work with Symfony2",
            __CLASS__,
            __METHOD__
        ));
    }


    /**
     * Trigger the user to perform a POST to the given URL with the given data.
     *
     * @param string $url
     * @param array $data
     * @return void
     */
    public function postRedirect(string $url, array $data = []): void
    {
        throw new BadMethodCallException(sprintf(
            "[TEST] %s:%s may not be called in the Surfnet\\SamlBundle as it doesn't work with Symfony2",
            __CLASS__,
            __METHOD__
        ));
    }


    /**
     * This function retrieves the path to a directory where temporary files can be saved.
     *
     * @throws \Exception If the temporary directory cannot be created or it exists and does not belong
     * to the current user.
     * @return string Path to a temporary directory, without a trailing directory separator.
     */
    public function getTempDir(): string
    {
        return sys_get_temp_dir();
    }


    /**
     * Atomically write a file.
     *
     * This is a helper function for writing data atomically to a file. It does this by writing the file data to a
     * temporary file, then renaming it to the required file name.
     *
     * @param string $filename The path to the file we want to write to.
     * @param string $data The data we should write to the file.
     * @param int $mode The permissions to apply to the file. Defaults to 0600.
     * @return void
     */
    public function writeFile(string $filename, string $data, int $mode = null): void
    {
        if ($mode === null) {
            $mode = 0600;
        }

        file_put_contents($filename, $data);
        chmod($filename, $mode);
    }
}
