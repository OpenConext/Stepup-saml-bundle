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
use SAML2\Assertion;
use Surfnet\SamlBundle\Exception\RuntimeException;
use Surfnet\SamlBundle\Exception\UnknownUrnException;
use Surfnet\SamlBundle\SAML2\Attribute\Filter\AttributeFilter;
use Traversable;

class AttributeSet implements AttributeSetFactory, AttributeSetInterface
{
    /**
     * @var Attribute[]
     */
    private array $attributes = [];

    public static function createFrom(Assertion $assertion, AttributeDictionary $attributeDictionary): AttributeSet
    {
        $attributeSet = new AttributeSet();

        foreach ($assertion->getAttributes() as $urn => $attributeValue) {
            try {
                $attribute = new Attribute(
                    $attributeDictionary->getAttributeDefinitionByUrn($urn),
                    $attributeValue
                );
                $attributeSet->initializeWith($attribute);
            } catch (UnknownUrnException $e) {
                if (!$attributeDictionary->ignoreUnknownAttributes()) {
                    throw $e;
                }
            }
        }

        return $attributeSet;
    }

    public static function create(array $attributes): AttributeSet
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

    public function apply(AttributeFilter $attributeFilter): AttributeSet
    {
        return self::create(array_filter($this->attributes, [$attributeFilter, 'allows']));
    }

    public function getAttributeByDefinition(AttributeDefinition $attributeDefinition): Attribute
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

    public function containsAttributeDefinedBy(AttributeDefinition $attributeDefinition): bool
    {
        foreach ($this->attributes as $attribute) {
            if ($attributeDefinition->equals($attribute->getAttributeDefinition())) {
                return true;
            }
        }

        return false;
    }

    public function contains(Attribute $otherAttribute): bool
    {
        foreach ($this->attributes as $attribute) {
            if ($attribute->equals($otherAttribute)) {
                return true;
            }
        }

        return false;
    }

    public function getIterator(): Traversable
    {
        return new ArrayIterator($this->attributes);
    }

    public function count(): int
    {
        return count($this->attributes);
    }

    /**
     * @SuppressWarnings(PHPMD.UnusedPrivateMethod) PHPMD does not see that this is being called in our static method
     */
    protected function initializeWith(Attribute $attribute): void
    {
        if ($this->contains($attribute)) {
            return;
        }

        $this->attributes[] = $attribute;
    }
}
