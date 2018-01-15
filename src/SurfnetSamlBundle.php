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

namespace Surfnet\SamlBundle;

use SAML2\Compat\ContainerSingleton;
use Surfnet\SamlBundle\DependencyInjection\Compiler\SamlAttributeRegistrationCompilerPass;
use Surfnet\SamlBundle\DependencyInjection\Compiler\SpRepositoryAliasCompilerPass;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\HttpKernel\Bundle\Bundle;

class SurfnetSamlBundle extends Bundle
{
    public function build(ContainerBuilder $container)
    {
        parent::build($container);

        $container->addCompilerPass(new SpRepositoryAliasCompilerPass());
        $container->addCompilerPass(new SamlAttributeRegistrationCompilerPass());
    }

    public function boot()
    {
        $bridgeContainer = $this->container->get('surfnet_saml.saml2.bridge_container');
        ContainerSingleton::setContainer($bridgeContainer);
    }
}
