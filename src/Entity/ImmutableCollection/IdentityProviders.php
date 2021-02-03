<?php

/**
 * Copyright 2017 SURFnet bv
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

namespace Surfnet\SamlBundle\Entity\ImmutableCollection;

use Surfnet\SamlBundle\Entity\IdentityProvider;

/**
 * Collection of identity providers
 *
 * Protects the integrity and provides low level logic functions.
 */
final class IdentityProviders
{
    private $identityProviders;

    /**
     *
     * @param IdentityProvider[] $identityProviders
     */
    public function __construct(array $identityProviders)
    {
        $this->identityProviders = array_values($identityProviders);
    }

    public function hasByEntityId($entityId)
    {
        return $this->findByEntityId($entityId) !== null;
    }

    public function findByEntityId($entityId)
    {
        return $this->find(function (IdentityProvider $provider) use ($entityId) {
            return $provider->getEntityId() === $entityId;
        });
    }

    private function find(callable $callback)
    {
        foreach ($this->identityProviders as $provider) {
            if ($callback($provider)) {
                return $provider;
            }
        }
        return null;
    }
}
