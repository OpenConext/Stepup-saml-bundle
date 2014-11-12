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

use SAML2_Assertion;
use Surfnet\SamlBundle\Exception\LogicException;
use Surfnet\SamlBundle\SAML2\Response\AssertionAdapter;

class AttributeDictionary
{
    /**
     * @var array
     */
    private $attributes = [];

    /**
     * @param AttributeDefinition $attribute
     */
    public function addAttributeDefinition(AttributeDefinition $attribute)
    {
        if (isset($this->attributes[$attribute->getName()])) {
            throw new LogicException(sprintf(
                'Cannot add attribute "%s" as it has already been added'
            ));
        }

        $this->attributes[$attribute->getName()] = $attribute;
    }

    /**
     * @param string $attribute
     * @return bool
     */
    public function hasAttributeDefinition($attribute)
    {
        return isset($this->attributes[$attribute]);
    }

    /**
     * @param string $attribute
     * @return AttributeDefinition
     */
    public function getAttributeDefinition($attribute)
    {
        if (!$this->hasAttributeDefinition($attribute)) {
            throw new LogicException(sprintf(
                'Cannot get AttributeDefinition "%s" as it has not been added to the collection',
                $attribute
            ));
        }

        return $this->attributes[$attribute];
    }

    /**
     * @param SAML2_Assertion $assertion
     * @return AssertionAdapter
     */
    public function translate(SAML2_Assertion $assertion)
    {
        return new AssertionAdapter($assertion, $this);
    }
}
