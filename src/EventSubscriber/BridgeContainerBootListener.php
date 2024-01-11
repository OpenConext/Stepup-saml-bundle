<?php

declare(strict_types = 1);

/**
 * Copyright 2019 SURFnet B.V.
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

namespace Surfnet\SamlBundle\EventSubscriber;

use SAML2\Compat\ContainerSingleton;
use Surfnet\SamlBundle\SAML2\BridgeContainer;
use Symfony\Component\EventDispatcher\EventSubscriberInterface;
use Symfony\Component\HttpKernel\Event\RequestEvent;
use Symfony\Component\HttpKernel\KernelEvents;

/**
 * When a request is triggered, set the ContainerSingleton to
 * be the BridgeContainer. We use the BridgeContainer to add some
 * convenience methods to the container like getting a specific
 * logger, or to create a traceable request id (sari).
 *
 * This is added in an event subscriber to ensure the container
 * is updated in time before other services start using it.
 */
class BridgeContainerBootListener implements EventSubscriberInterface
{
    public function __construct(private readonly BridgeContainer $bridgeContainer)
    {
    }

    public static function getSubscribedEvents(): array
    {
        return [
            KernelEvents::REQUEST => ['onKernelRequest', 600],
        ];
    }

    public function onKernelRequest(RequestEvent $event): void
    {
        ContainerSingleton::setContainer($this->bridgeContainer);
    }
}
