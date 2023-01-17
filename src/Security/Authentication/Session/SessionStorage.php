<?php

/**
 * Copyright 2017 SURFnet B.V.
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

namespace Surfnet\SamlBundle\Security\Authentication\Session;

use Surfnet\SamlBundle\Security\Authentication\AuthenticatedSessionStateHandler;
use Surfnet\SamlBundle\Security\Authentication\SamlAuthenticationStateHandler;
use Surfnet\SamlBundle\Security\Exception\LogicException;
use Surfnet\SamlBundle\Value\DateTime;
use Symfony\Component\HttpFoundation\Session\SessionInterface;

class SessionStorage implements AuthenticatedSessionStateHandler, SamlAuthenticationStateHandler
{
    /**
     * Session keys
     */
    const AUTH_SESSION_KEY = '__auth/';
    const SAML_SESSION_KEY = '__saml/';

    public function __construct(private readonly SessionInterface $session)
    {
    }

    public function logAuthenticationMoment()
    {
        if ($this->isAuthenticationMomentLogged()) {
            throw new LogicException('Cannot log authentication moment as an authentication moment is already logged');
        }

        $this->session->set(self::AUTH_SESSION_KEY . 'authenticated_at', DateTime::now()->format(DateTime::FORMAT));
        $this->updateLastInteractionMoment();
    }

    public function isAuthenticationMomentLogged()
    {
        return $this->session->get(self::AUTH_SESSION_KEY . 'authenticated_at', null) !== null;
    }

    public function getAuthenticationMoment()
    {
        if (!$this->isAuthenticationMomentLogged()) {
            throw new LogicException('Cannot get last authentication moment as no authentication has been set');
        }

        return DateTime::fromString($this->session->get(self::AUTH_SESSION_KEY . 'authenticated_at'));
    }

    public function updateLastInteractionMoment()
    {
        $this->session->set(self::AUTH_SESSION_KEY . 'last_interaction', DateTime::now()->format(DateTime::FORMAT));
    }

    public function hasSeenInteraction()
    {
        return $this->session->get(self::AUTH_SESSION_KEY . 'last_interaction', null) !== null;
    }

    public function getLastInteractionMoment()
    {
        if (!$this->hasSeenInteraction()) {
            throw new LogicException('Cannot get last interaction moment as we have not seen any interaction');
        }

        return DateTime::fromString($this->session->get(self::AUTH_SESSION_KEY . 'last_interaction'));
    }

    public function setCurrentRequestUri($uri)
    {
        $this->session->set(self::AUTH_SESSION_KEY . 'current_uri', $uri);
    }

    public function getCurrentRequestUri(): string
    {
        $uri = $this->session->get(self::AUTH_SESSION_KEY . 'current_uri');
        $this->session->remove(self::AUTH_SESSION_KEY . 'current_uri');

        return $uri;
    }

    public function getRequestId(): string
    {
        return $this->session->get(self::SAML_SESSION_KEY . 'request_id');
    }

    public function setRequestId(string $requestId): void
    {
        $this->session->set(self::SAML_SESSION_KEY . 'request_id', $requestId);
    }

    public function hasRequestId(): bool
    {
        $value =  $this->session->has(self::SAML_SESSION_KEY . 'request_id');
        return $value;
    }

    public function clearRequestId(): void
    {
        $this->session->remove(self::SAML_SESSION_KEY . 'request_id');
    }

    public function invalidate()
    {
        $this->session->invalidate();
    }

    public function migrate()
    {
        $this->session->migrate();
    }
}
