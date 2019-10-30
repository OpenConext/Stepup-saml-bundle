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

namespace Surfnet\SamlBundle\Entity;

use Surfnet\SamlBundle\Entity\ImmutableCollection\IdentityProviders;
use Surfnet\SamlBundle\Exception\NotFound;

final class StaticIdentityProviderRepository implements IdentityProviderRepository
{
    private $identityProviders;

    /**
     *
     * @param IdentityProvider[] $identityProviders
     */
    public function __construct(array $identityProviders)
    {
        $this->identityProviders = new IdentityProviders($identityProviders);
    }

    /**
     * @param string $entityId
     * @return IdentityProvider
     * @throws NotFound
     */
    public function getIdentityProvider($entityId)
    {
        $identityProvider = $this->identityProviders->findByEntityId($entityId);
        if ($identityProvider) {
            return $identityProvider;
        }

        throw NotFound::identityProvider($entityId);
    }

    /**
     * @param string $entityId
     * @return bool
     */
    public function hasIdentityProvider($entityId)
    {
        return $this->identityProviders->hasByEntityId($entityId);
    }
}
