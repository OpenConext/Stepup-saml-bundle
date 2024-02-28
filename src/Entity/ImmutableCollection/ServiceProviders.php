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

use Surfnet\SamlBundle\Entity\ServiceProvider;

/**
 * Collection of service provider
 *
 * Protects the integrity and provides low level logic functions.
 */
final class ServiceProviders
{
    private readonly array $serviceProviders;

    /**
     *
     * @param ServiceProvider[] $serviceProviders
     */
    public function __construct(array $serviceProviders)
    {
        $this->serviceProviders = array_values($serviceProviders);
    }

    public function hasByEntityId($entityId): bool
    {
        return $this->findByEntityId($entityId) !== null;
    }

    public function findByEntityId($entityId)
    {
        return $this->find(fn(ServiceProvider $provider): bool => $provider->getEntityId() === $entityId);
    }

    private function find(callable $callback)
    {
        foreach ($this->serviceProviders as $provider) {
            if ($callback($provider)) {
                return $provider;
            }
        }
        return null;
    }
}
