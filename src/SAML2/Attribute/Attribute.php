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
    private $values;

    /**
     * @param AttributeDefinition $attributeDefinition
     * @param string[] $values
     */
    public function __construct(AttributeDefinition $attributeDefinition, array $values)
    {
        $this->attributeDefinition = $attributeDefinition;
        $this->values = $values;
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
    public function getValues()
    {
        return $this->values;
    }

    /**
     * @param Attribute $other
     * @return bool
     */
    public function equals(Attribute $other)
    {
        return $this->attributeDefinition->equals($other->attributeDefinition) && $this->values === $other->values;
    }
}
