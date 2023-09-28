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

namespace Surfnet\SamlBundle\DependencyInjection\Compiler;

use Symfony\Component\DependencyInjection\Compiler\CompilerPassInterface;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Reference;

class SamlAttributeRegistrationCompilerPass implements CompilerPassInterface
{
    /**
     * @param ContainerBuilder $container
     *
     * @SuppressWarnings(PHPMD.UnusedLocalVariable) - $tagData is simply not used
     */
    public function process(ContainerBuilder $container): void
    {
        if (!$container->hasDefinition('surfnet_saml.saml.attribute_dictionary')) {
            return;
        }

        $collection = $container->getDefinition('surfnet_saml.saml.attribute_dictionary');
        $attributes = $container->findTaggedServiceIds('saml.attribute');

        foreach (array_keys($attributes) as $id) {
            $collection->addMethodCall('addAttributeDefinition', [new Reference($id)]);
        }
    }
}
