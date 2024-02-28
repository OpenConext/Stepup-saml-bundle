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

namespace Surfnet\SamlBundle\SAML2\Attribute;

use SAML2\Assertion;
use Surfnet\SamlBundle\Exception\InvalidArgumentException;

final class ConfigurableAttributeSetFactory implements AttributeSetFactory
{
    private static string $attributeSetClassName = AttributeSet::class;

    /**
     * @param string $attributeSetClassName
     */
    public static function configureWhichAttributeSetToCreate($attributeSetClassName): void
    {
        if (!is_string($attributeSetClassName) || $attributeSetClassName === '') {
            throw InvalidArgumentException::invalidType('non-empty string', 'attributeSetClassName', $attributeSetClassName);
        }

        if (!is_a($attributeSetClassName, '\Surfnet\SamlBundle\SAML2\Attribute\AttributeSetFactory', true)) {
            throw new InvalidArgumentException(sprintf(
                'Cannot use class "%s": it must implement "%s"',
                $attributeSetClassName,
                AttributeSetFactory::class
            ));
        }

        self::$attributeSetClassName = $attributeSetClassName;
    }

    public static function createFrom(
        Assertion $assertion,
        AttributeDictionary $attributeDictionary
    ): AttributeSetInterface {
        $class = self::$attributeSetClassName;

        return $class::createFrom($assertion, $attributeDictionary);
    }

    public static function create(array $attributes): AttributeSetInterface
    {
        $class = self::$attributeSetClassName;

        return $class::create($attributes);
    }
}
