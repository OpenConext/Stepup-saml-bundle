<?php

/**
 * Copyright 2016 SURFnet B.V.
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

namespace Surfnet\SamlBundle\Tests\Unit\SAML2\Attribute\Mock;

use SAML2\Assertion;
use Surfnet\SamlBundle\SAML2\Attribute\Attribute;
use Surfnet\SamlBundle\SAML2\Attribute\AttributeDefinition;
use Surfnet\SamlBundle\SAML2\Attribute\AttributeDictionary;
use Surfnet\SamlBundle\SAML2\Attribute\AttributeSetFactory;
use Surfnet\SamlBundle\SAML2\Attribute\AttributeSetInterface;
use Surfnet\SamlBundle\SAML2\Attribute\Filter\AttributeFilter;
use Traversable;

final class DummyAttributeSet implements AttributeSetFactory, AttributeSetInterface
{
    public static function createFrom(Assertion $assertion, AttributeDictionary $attributeDictionary): AttributeSetInterface
    {
        return new self;
    }

    public static function create(array $attributes): AttributeSetInterface
    {
        return new self;
    }

    public function apply(AttributeFilter $attributeFilter): AttributeSetInterface
    {
        // TODO: Implement apply() method.
    }

    public function getAttributeByDefinition(AttributeDefinition $attributeDefinition): Attribute
    {
        // TODO: Implement getAttributeByDefinition() method.
    }

    public function containsAttributeDefinedBy(AttributeDefinition $attributeDefinition): bool
    {
        // TODO: Implement containsAttributeDefinedBy() method.
    }

    public function contains(Attribute $otherAttribute): bool
    {
        // TODO: Implement contains() method.
    }

    public function getIterator(): Traversable
    {
        // TODO: Implement getIterator() method.
    }

    public function count(): int
    {
        // TODO: Implement count() method.
    }
}
