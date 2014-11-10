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

namespace Surfnet\SamlBundle\DependencyInjection;

use Symfony\Component\Config\Definition\Builder\ArrayNodeDefinition;
use Symfony\Component\Config\Definition\Builder\TreeBuilder;
use Symfony\Component\Config\Definition\ConfigurationInterface;

/**
 * This is the class that validates and merges configuration from your app/config files
 *
 * To learn more see {@link http://symfony.com/doc/current/cookbook/bundles/extension.html#cookbook-bundles-extension-config-class}
 */
class Configuration implements ConfigurationInterface
{
    /**
     * {@inheritdoc}
     */
    public function getConfigTreeBuilder()
    {
        $treeBuilder = new TreeBuilder();
        $rootNode = $treeBuilder->root('surfnet_saml');

        $this->addMetadataSection($rootNode);
        $this->addRemoteSection($rootNode);

        return $treeBuilder;
    }

    /**
     * @param ArrayNodeDefinition $node
     */
    private function addMetadataSection(ArrayNodeDefinition $node)
    {
        $node
            ->children()
            ->arrayNode('hosted')
                ->children()
                    ->arrayNode('service_provider')
                        ->canBeEnabled()
                        ->children()
                            ->scalarNode('assertion_consumer_route')
                                ->defaultNull()
                                ->info('The name of the route to generate the assertion consumer URL')
                            ->end()
                            ->scalarNode('public_key')
                                ->defaultNull()
                                ->info('The absolute path to the public key used to sign AuthnRequests')
                            ->end()
                            ->scalarNode('private_key')
                                ->defaultNull()
                                ->info('The absolute path to the private key used to sign AuthnRequests')
                            ->end()
                        ->end()
                    ->end()
                    ->arrayNode('identity_provider')
                        ->canBeEnabled()
                        ->children()
                            ->scalarNode('sso_route')
                                ->defaultNull()
                                ->info('The name of the route to generate the SSO URL')
                            ->end()
                            ->scalarNode('service_provider_repository')
                                ->defaultNull()
                                ->info(
                                    'Name of the service that is the Entity Repository. Must implement the '
                                    . ' Surfnet\SamlBundle\Entity\ServiceProviderRepository interface.'
                                )
                            ->end()
                            ->scalarNode('certificate')
                                ->defaultNull()
                                ->info(
                                    'The contents of the certificate used to sign the AuthnResponse with, if different from'
                                    . ' the public key configured below'
                                )
                            ->end()
                            ->scalarNode('public_key')
                                ->defaultNull()
                                ->info('The absolute path to the public key used to sign Responses to AuthRequests with')
                            ->end()
                            ->scalarNode('private_key')
                                ->defaultNull()
                                ->info('The absolute path to the private key used to sign Responses to AuthRequests with')
                            ->end()
                        ->end()
                    ->end()
                    ->arrayNode('metadata')
                        ->children()
                        ->scalarNode('entity_id_route')
                            ->defaultNull()
                            ->info('The name of the route used to generate the entity id')
                        ->end()
                        ->scalarNode('public_key')
                            ->defaultNull()
                            ->info('The absolute path to the public key used to sign the metadata')
                        ->end()
                        ->scalarNode('private_key')
                            ->defaultNull()
                            ->info('The absolute path to the private key used to sign the metadata')
                        ->end()
                    ->end()
                ->end()
            ->end();
    }

    private function addRemoteSection(ArrayNodeDefinition $rootNode)
    {
        $remoteNode = $rootNode
            ->children()
            ->arrayNode('remote');

        $this->addRemoteIdentityProviderSection($remoteNode);
    }

    private function addRemoteIdentityProviderSection(ArrayNodeDefinition $remoteNode)
    {
        $remoteNode
            ->children()
            ->arrayNode('identity_provider')
                ->canBeEnabled()
                ->children()
                    ->scalarNode('entity_id')
                        ->isRequired()
                        ->info('The EntityID of the remote identity provider')
                    ->end()
                    ->scalarNode('sso_url')
                        ->isRequired()
                        ->info('The name of the route to generate the SSO URL')
                    ->end()
                    ->scalarNode('certificate')
                        ->isRequired()
                        ->info(
                            'The contents of the certificate used to sign the AuthnResponse with, if different from'
                            . ' the public key configured below'
                        )
                    ->end()
                ->end()
            ->end();
    }
}
