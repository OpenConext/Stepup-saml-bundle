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

use Surfnet\SamlBundle\Entity\ImmutableCollection\ServiceProviders;
use Surfnet\SamlBundle\Exception\NotFound;

final class StaticServiceProviderRepository implements ServiceProviderRepository
{
    private $serviceProviders;

    /**
     *
     * @param ServiceProvider[] $serviceProviders
     */
    public function __construct(array $serviceProviders)
    {
        $this->serviceProviders = new ServiceProviders($serviceProviders);
    }

    /**
     * @param string $entityId
     * @return ServiceProvider
     * @throws NotFound
     */
    public function getServiceProvider($entityId)
    {
        $serviceProvider = $this->serviceProviders->findByEntityId($entityId);
        if ($serviceProvider) {
            return $serviceProvider;
        }
        throw NotFound::identityProvider($entityId);
    }

    /**
     * @param string $entityId
     * @return bool
     */
    public function hasServiceProvider($entityId)
    {
        return $this->serviceProviders->hasByEntityId($entityId);
    }
}
