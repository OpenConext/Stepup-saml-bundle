<?php declare(strict_types=1);

/**
 * Copyright 2023 SURFnet B.V.
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

namespace Surfnet\SamlBundle\Security\Authentication;

use Surfnet\SamlBundle\Value\DateTime;

interface AuthenticatedSessionStateHandler
{
    /**
     * Sets the moment at which the user was authenticated
     *
     * @throws \LogicException when an authentication moment was already logged
     */
    public function logAuthenticationMoment(): void;

    public function isAuthenticationMomentLogged(): bool;

    /**
     * Gets the moment at which the user was authenticated
     *
     * @throws \LogicException when no authentication moment was logged
     */
    public function getAuthenticationMoment(): DateTime;

    /**
     * Updates the last interaction moment to the current moment
     */
    public function updateLastInteractionMoment(): void;

    /**
     * Retrieves the last interaction moment
     */
    public function getLastInteractionMoment(): DateTime;

    public function hasSeenInteraction(): bool;

    public function setCurrentRequestUri(string $uri);

    public function getCurrentRequestUri(): string;

    /**
     * Migrates the current session to a new session id while maintaining all
     * session attributes.
     */
    public function migrate(): void;

    /**
     * Invalidates the session
     *
     * Clears all session attributes and flashes and regenerates the
     * session and deletes the old session from persistence
     */
    public function invalidate(): void;
}
