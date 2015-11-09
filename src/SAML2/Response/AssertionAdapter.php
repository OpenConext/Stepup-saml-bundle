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

namespace Surfnet\SamlBundle\SAML2\Response;

use SAML2_Assertion;
use Surfnet\SamlBundle\Exception\UnexpectedValueException;
use Surfnet\SamlBundle\SAML2\Attribute\Attribute;
use Surfnet\SamlBundle\SAML2\Attribute\AttributeDefinition;
use Surfnet\SamlBundle\SAML2\Attribute\AttributeDictionary;
use Surfnet\SamlBundle\SAML2\Attribute\AttributeList;
use Surfnet\SamlBundle\SAML2\Attribute\AttributeSet;
use Symfony\Component\DependencyInjection\ParameterBag\ParameterBag;

class AssertionAdapter
{
    /**
     * @var SAML2_Assertion
     */
    private $assertion;

    /**
     * @var AttributeSet
     */
    private $attributeSet;

    /**
     * @var \Surfnet\SamlBundle\SAML2\Attribute\AttributeDictionary
     */
    private $attributeDictionary;

    public function __construct(SAML2_Assertion $assertion, AttributeDictionary $attributeDictionary)
    {
        $this->assertion           = $assertion;
        $this->attributeSet        = AttributeSet::createFrom($assertion, $attributeDictionary);
        $this->attributeDictionary = $attributeDictionary;
    }

    /**
     * @return string
     */
    public function getNameID()
    {
        $data = $this->assertion->getNameId();
        if (is_array($data) && array_key_exists('Value', $data)) {
            return $data['Value'];
        }

        return null;
    }

    /**
     * Attempt to get an attribute from the assertion.
     *
     * @deprecated use getAttributeValue instead, to be removed in 2.0
     *
     * @param string $name
     * @param null   $default
     * @return null|string[]
     */
    public function getAttribute($name, $default = null)
    {
        return $this->getAttributeValue($name, $default);
    }

    /**
     * @param string $attributeName
     * @param null   $defaultValue
     * @return null|string[]
     */
    public function getAttributeValue($attributeName, $defaultValue = null)
    {
        $attributeDefinition = $this->attributeDictionary->getAttributeDefinition($attributeName);

        if (!$this->attributeSet->containsAttributeDefinedBy($attributeDefinition)) {
            return $defaultValue;
        }

        $attribute = $this->attributeSet->getAttributeByDefinition($attributeDefinition);

        return $attribute->getValue();
    }

    /**
     * @return AttributeSet
     */
    public function getAttributeSet()
    {
        return $this->attributeSet;
    }
}
