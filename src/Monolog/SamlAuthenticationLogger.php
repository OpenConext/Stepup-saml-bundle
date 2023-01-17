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
use Surfnet\SamlBundle\Exception\RuntimeException;

/**
 * Decorates a PSR logger and adds information pertaining to a SAML request procedure to each message's context.
 *
 * @SuppressWarnings(PHPMD.TooManyPublicMethods)
 */
final class SamlAuthenticationLogger implements LoggerInterface
{
    private LoggerInterface $logger;

    private ?string $sari;

    public function __construct(LoggerInterface $logger)
    {
        $this->logger = $logger;
    }

    /**
     * @param string $requestId The SAML authentication request ID of the initial request (not subsequent proxy requests).
     */
    public function forAuthentication(string $requestId): self
    {
        $logger = new self($this->logger);
        $logger->sari = $requestId;

        return $logger;
    }

    public function emergency($message, array $context = []): void
    {
        $this->logger->emergency($message, $this->modifyContext($context));
    }

    public function alert($message, array $context = []): void
    {
        $this->logger->alert($message, $this->modifyContext($context));
    }

    public function critical($message, array $context = []): void
    {
        $this->logger->critical($message, $this->modifyContext($context));
    }

    public function error($message, array $context = []): void
    {
        $this->logger->error($message, $this->modifyContext($context));
    }

    public function warning($message, array $context = []): void
    {
        $this->logger->warning($message, $this->modifyContext($context));
    }

    public function notice($message, array $context = []): void
    {
        $this->logger->notice($message, $this->modifyContext($context));
    }

    public function info($message, array $context = []): void
    {
        $this->logger->info($message, $this->modifyContext($context));
    }

    public function debug($message, array $context = []): void
    {
        $this->logger->debug($message, $this->modifyContext($context));
    }

    public function log($level, $message, array $context = []): void
    {
        $this->logger->log($level, $message, $this->modifyContext($context));
    }

    /**
     * Adds the SARI to the log context
     */
    private function modifyContext(array $context): array
    {
        if (!$this->sari) {
            throw new RuntimeException('Authentication logging context is unknown');
        }

        $context['sari'] = $this->sari;

        return $context;
    }
}
