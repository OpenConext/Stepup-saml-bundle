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

use Surfnet\SamlBundle\Security\Exception\LogicException;
use Surfnet\SamlBundle\Value\DateTime;

interface AuthenticatedSessionStateHandler
{
    /**
     * Sets the moment at which the user was authenticated
     *
     * @return void
     * @throws LogicException when an authentication moment was already logged
     */
    public function logAuthenticationMoment();

    /**
     * @return bool
     */
    public function isAuthenticationMomentLogged();

    /**
     * Gets the moment at which the user was authenticated
     *
     * @return DateTime
     * @throws LogicException when no authentication moment was logged
     */
    public function getAuthenticationMoment();

    /**
     * Updates the last interaction moment to the current moment
     *
     * @return void
     */
    public function updateLastInteractionMoment();

    /**
     * Retrieves the last interaction moment
     *
     * @return DateTime
     */
    public function getLastInteractionMoment();

    /**
     * @return bool
     */
    public function hasSeenInteraction();

    /**
     * @param string $uri
     */
    public function setCurrentRequestUri($uri);

    /**
     * @return string
     */
    public function getCurrentRequestUri();

    /**
     * Migrates the current session to a new session id while maintaining all
     * session attributes.
     */
    public function migrate();

    /**
     * Invalidates the session
     *
     * Clears all session attributes and flashes and regenerates the
     * session and deletes the old session from persistence
     */
    public function invalidate();
}
