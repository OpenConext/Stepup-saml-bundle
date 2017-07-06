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

namespace Surfnet\SamlBundle\Monolog;

use Psr\Log\LoggerInterface;
use Surfnet\SamlBundle\Exception\InvalidArgumentException;
use Surfnet\SamlBundle\Exception\RuntimeException;

/**
 * Decorates a PSR logger and adds information pertaining to a SAML request procedure to each message's context.
 *
 * @SuppressWarnings(PHPMD.TooManyPublicMethods)
 */
final class SamlAuthenticationLogger implements LoggerInterface
{
    /**
     * @var \Psr\Log\LoggerInterface
     */
    private $logger;

    /**
     * @var string|null
     */
    private $sari;

    public function __construct(LoggerInterface $logger)
    {
        $this->logger = $logger;
    }

    /**
     * @param string $requestId The SAML authentication request ID of the initial request (not subsequent proxy requests).
     * @return self
     */
    public function forAuthentication($requestId)
    {
        if (!is_string($requestId)) {
            throw InvalidArgumentException::invalidType('string', 'requestId', $requestId);
        }

        $logger = new self($this->logger);
        $logger->sari = $requestId;

        return $logger;
    }

    public function emergency($message, array $context = [])
    {
        $this->logger->emergency($message, $this->modifyContext($context));
    }

    public function alert($message, array $context = [])
    {
        $this->logger->alert($message, $this->modifyContext($context));
    }

    public function critical($message, array $context = [])
    {
        $this->logger->critical($message, $this->modifyContext($context));
    }

    public function error($message, array $context = [])
    {
        $this->logger->error($message, $this->modifyContext($context));
    }

    public function warning($message, array $context = [])
    {
        $this->logger->warning($message, $this->modifyContext($context));
    }

    public function notice($message, array $context = [])
    {
        $this->logger->notice($message, $this->modifyContext($context));
    }

    public function info($message, array $context = [])
    {
        $this->logger->info($message, $this->modifyContext($context));
    }

    public function debug($message, array $context = [])
    {
        $this->logger->debug($message, $this->modifyContext($context));
    }

    public function log($level, $message, array $context = [])
    {
        $this->logger->log($level, $message, $this->modifyContext($context));
    }

    /**
     * Adds the SARI to the log context.
     *
     * @param array $context
     * @return array
     */
    private function modifyContext(array $context)
    {
        if (!$this->sari) {
            throw new RuntimeException('Authentication logging context is unknown');
        }

        $context['sari'] = $this->sari;

        return $context;
    }
}
