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

use Symfony\Component\Config\Definition\Builder\NodeBuilder;
use Symfony\Component\Config\Definition\Builder\NodeDefinition;
use Symfony\Component\Config\Definition\Builder\TreeBuilder;
use Symfony\Component\Config\Definition\ConfigurationInterface;

/**
 * This is the class that validates and merges configuration from your app/config files
 *
 * To learn more see {@link http://symfony.com/doc/current/cookbook/bundles/extension.html#cookbook-bundles-extension-config-class}
 */
class Configuration implements ConfigurationInterface
{
    public function __construct(NodeDefinition $rootNode)
    {
        $this->addHostedSection($rootNode);
        $this->addRemoteSection($rootNode);
    }

    /**
     * {@inheritdoc}
     */
    public function getConfigTreeBuilder()
    {
        $treeBuilder = new TreeBuilder('surfnet_saml');
        $rootNode = $treeBuilder->getRootNode();

        $this->addHostedSection($rootNode);
        $this->addRemoteSection($rootNode);

        return $treeBuilder;
    }

    private function addHostedSection(NodeDefinition $node): void
    {
        $node
            ->children()
            ->arrayNode('hosted')
                ->children()
                    ->arrayNode('attribute_dictionary')
                        ->canBeEnabled()
                        ->children()
                            ->booleanNode('ignore_unknown_attributes')
                            ->defaultFalse()
                            ->info(
                                'If the IDP provides atttributes which are not in the dictionary the SAML assertion'
                                . 'will fail with an UnknownUrnException. Unless this value is true.'
                            )
                            ->end()
                        ->end()
                    ->end()
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

    private function addRemoteSection(NodeDefinition $rootNode): void
    {
        $remoteNode = $rootNode
            ->children()
            ->arrayNode('remote');

        $this->addRemoteIdentityProvidersSection($remoteNode);
        $this->addRemoteServiceProvidersSection($remoteNode);

        // For backwards compatibility: support configuring a single remote IDP
        $this->addRemoteIdentityProviderSection($remoteNode);
    }

    private function addRemoteIdentityProviderSection(NodeDefinition $remoteNode): void
    {
        $arrayNode = $remoteNode
            ->children()
            ->arrayNode('identity_provider')
                ->canBeEnabled()
                ->children();

        $this->addRemoteIdentityProviderConfiguration($arrayNode);
    }


    private function addRemoteIdentityProviderConfiguration(NodeBuilder $arrayNode): void
    {
        $arrayNode
          ->scalarNode('entity_id')
              ->isRequired()
              ->info('The EntityID of the remote identity provider')
          ->end()
          ->scalarNode('sso_url')
              ->isRequired()
              ->info('The name of the route to generate the SSO URL')
          ->end()
          ->scalarNode('certificate')
              ->info(
                  'The contents of the certificate used to sign the AuthnResponse with'
              )
          ->end()
          ->scalarNode('certificate_file')
              ->info(
                  'A file containing the certificate used to sign the AuthnResponse with'
              )
          ->end();
    }

    private function addRemoteIdentityProvidersSection(NodeDefinition $remoteNode): void
    {
        $arrayNode = $remoteNode
            ->children()
                ->arrayNode('identity_providers')
                     ->prototype('array')
                        ->children();

        $this->addRemoteIdentityProviderConfiguration($arrayNode);

        $arrayNode
                      ->end()
                  ->end()
              ->end()
          ->end();
    }

    private function addRemoteServiceProvidersSection(NodeDefinition $remoteNode): void
    {
        $remoteNode
            ->children()
                ->arrayNode('service_providers')
                    ->prototype('array')
                        ->children()
                            ->scalarNode('entity_id')
                                ->isRequired()
                                ->info('The EntityID of the remote service provider')
                            ->end()
                            ->scalarNode('certificate')
                                ->info(
                                    'The contents of the certificate used to sign and verify the AuthnResponse with'
                                )
                            ->end()
                            ->scalarNode('certificate_file')
                                ->info(
                                    'A file containing the certificate used to sign and verify the AuthnResponse with'
                                )
                            ->end()
                            ->scalarNode('assertion_consumer_service_url')
                                ->isRequired()
                            ->end()
                        ->end()
                    ->end()
                ->end()
            ->end();
    }
}
