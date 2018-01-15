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

namespace Surfnet\SamlBundle\SAML2\Attribute;

use SAML2\Assertion;
use Surfnet\SamlBundle\Exception\InvalidArgumentException;
use Surfnet\SamlBundle\Exception\LogicException;
use Surfnet\SamlBundle\Exception\UnknownUrnException;
use Surfnet\SamlBundle\SAML2\Response\AssertionAdapter;

class AttributeDictionary
{
    /**
     * @var AttributeDefinition[]
     */
    private $attributeDefinitionsByName = [];

    /**
     * @var AttributeDefinition[]
     */
    private $attributeDefinitionsByUrn = [];

    /**
     * Ignore unknown attributes coming from the IDP
     *
     * @var bool
     */
    private $ignoreUnknowAttributes = false;

    /**
     * AttributeDictionary constructor.
     *
     * @param bool $ignoreUnknowAttributes
     */
    public function __construct($ignoreUnknowAttributes = false)
    {
        $this->ignoreUnknowAttributes = $ignoreUnknowAttributes;
    }

    /**
     * Whether to ignore unknown SAML attributes.
     *
     * @return bool
     */
    public function ignoreUnknownAttributes()
    {
        return $this->ignoreUnknowAttributes;
    }

    /**
     * @param AttributeDefinition $attributeDefinition
     *
     * We store the definitions indexed both by name and by urn to ensure speedy lookups due to the amount of
     * definitions and the amount of usages of the lookups
     */
    public function addAttributeDefinition(AttributeDefinition $attributeDefinition)
    {
        if (isset($this->attributeDefinitionsByName[$attributeDefinition->getName()])) {
            throw new LogicException(sprintf(
                'Cannot add attribute "%s" as it has already been added',
                $attributeDefinition->getName()
            ));
        }

        $this->attributeDefinitionsByName[$attributeDefinition->getName()] = $attributeDefinition;

        if ($attributeDefinition->hasUrnMace()) {
            $this->attributeDefinitionsByUrn[$attributeDefinition->getUrnMace()] = $attributeDefinition;
        }

        if ($attributeDefinition->hasUrnOid()) {
            $this->attributeDefinitionsByUrn[$attributeDefinition->getUrnOid()] = $attributeDefinition;
        }
    }

    /**
     * @param Assertion $assertion
     * @return AssertionAdapter
     */
    public function translate(Assertion $assertion)
    {
        return new AssertionAdapter($assertion, $this);
    }

    /**
     * @param string $attributeName
     * @return bool
     */
    public function hasAttributeDefinition($attributeName)
    {
        return isset($this->attributeDefinitionsByName[$attributeName]);
    }

    /**
     * @param string $attributeName
     * @return AttributeDefinition
     */
    public function getAttributeDefinition($attributeName)
    {
        if (!$this->hasAttributeDefinition($attributeName)) {
            throw new LogicException(sprintf(
                'Cannot get AttributeDefinition "%s" as it has not been added to the collection',
                $attributeName
            ));
        }

        return $this->attributeDefinitionsByName[$attributeName];
    }

    /**
     * @param string $urn
     * @return AttributeDefinition|null
     */
    public function findAttributeDefinitionByUrn($urn)
    {
        if (!is_string($urn) || empty($urn)) {
            throw InvalidArgumentException::invalidType('non-empty string', $urn, 'urn');
        }

        if (array_key_exists($urn, $this->attributeDefinitionsByUrn)) {
            return $this->attributeDefinitionsByUrn[$urn];
        }

        return null;
    }

    /**
     * @param string $urn
     * @return AttributeDefinition
     */
    public function getAttributeDefinitionByUrn($urn)
    {
        if (!is_string($urn) || empty($urn)) {
            throw InvalidArgumentException::invalidType('non-empty string', $urn, 'urn');
        }

        if (array_key_exists($urn, $this->attributeDefinitionsByUrn)) {
            return $this->attributeDefinitionsByUrn[$urn];
        }

        throw new UnknownUrnException($urn);
    }
}
