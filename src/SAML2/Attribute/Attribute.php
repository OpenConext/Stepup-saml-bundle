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

class Attribute
{
    /**
     * @var AttributeDefinition
     */
    private $attributeDefinition;

    /**
     * @var string[]
     */
    private $value;

    /**
     * @param AttributeDefinition $attributeDefinition
     * @param string[] $value
     */
    public function __construct(AttributeDefinition $attributeDefinition, array $value)
    {
        $this->attributeDefinition = $attributeDefinition;
        $this->value               = $value;
    }

    /**
     * @return AttributeDefinition
     */
    public function getAttributeDefinition()
    {
        return $this->attributeDefinition;
    }

    /**
     * @return string[]
     */
    public function getValue()
    {
        return $this->value;
    }

    /**
     * @param Attribute $other
     * @return bool
     */
    public function equals(Attribute $other)
    {
        return $this->attributeDefinition->equals($other->attributeDefinition) && $this->value === $other->value;
    }
}
