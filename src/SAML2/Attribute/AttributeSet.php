<?php

/**
 * Copyright 2015 SURFnet B.V.
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

use ArrayIterator;
use Countable;
use IteratorAggregate;
use SAML2_Assertion;
use Surfnet\SamlBundle\Exception\RuntimeException;
use Surfnet\SamlBundle\SAML2\Attribute\Filter\AttributeSetFilterInterface;

final class AttributeSet implements IteratorAggregate, Countable
{
    /**
     * @var Attribute[]
     */
    private $attributes = [];

    /**
     * @param SAML2_Assertion $assertion
     * @param AttributeDictionary $attributeDictionary
     * @return AttributeSet
     */
    public static function createFrom(SAML2_Assertion $assertion, AttributeDictionary $attributeDictionary)
    {
        $attributeSet = new AttributeSet();

        foreach ($assertion->getAttributes() as $urn => $attributeValue) {
            $attribute = new Attribute($attributeDictionary->getAttributeDefinitionByUrn($urn), $attributeValue);
            $attributeSet->initializeWith($attribute);
        }

        return $attributeSet;
    }

    /**
     * @param Attribute[] $attributes
     * @return AttributeSet
     */
    public static function create(array $attributes)
    {
        $attributeSet = new AttributeSet();

        foreach ($attributes as $attribute) {
            $attributeSet->initializeWith($attribute);
        }

        return $attributeSet;
    }

    private function __construct()
    {
    }

    /**
     * @param AttributeSetFilterInterface $attributeFilter
     * @return AttributeSet
     */
    public function apply(AttributeSetFilterInterface $attributeFilter)
    {
        return self::create($attributeFilter->applyOn($this->attributes));
    }

    /**
     * @param AttributeDefinition $attributeDefinition
     * @return Attribute
     */
    public function getAttributeByDefinition(AttributeDefinition $attributeDefinition)
    {
        foreach ($this->attributes as $attribute) {
            if ($attributeDefinition->equals($attribute->getAttributeDefinition())) {
                return $attribute;
            }
        }

        throw new RuntimeException(sprintf(
            'Attempted to get unknown attribute defined by "%s"',
            $attributeDefinition->getName()
        ));
    }

    /**
     * @param AttributeDefinition $attributeDefinition
     * @return bool
     */
    public function containsAttributeDefinedBy(AttributeDefinition $attributeDefinition)
    {
        foreach ($this->attributes as $attribute) {
            if ($attributeDefinition->equals($attribute->getAttributeDefinition())) {
                return true;
            }
        }

        return false;
    }

    /**
     * @param Attribute $otherAttribute
     * @return bool
     */
    public function contains(Attribute $otherAttribute)
    {
        foreach ($this->attributes as $attribute) {
            if ($attribute->equals($otherAttribute)) {
                return true;
            }
        }

        return false;
    }

    public function getIterator()
    {
        return new ArrayIterator($this->attributes);
    }

    public function count()
    {
        return count($this->attributes);
    }

    /**
     * @param Attribute $attribute
     *
     * @SuppressWarnings(PHPMD.UnusedPrivateMethod) PHPMD does not see that this is being called in our static method
     */
    private function initializeWith(Attribute $attribute)
    {
        if ($this->contains($attribute)) {
            return;
        }

        $this->attributes[] = $attribute;
    }
}
