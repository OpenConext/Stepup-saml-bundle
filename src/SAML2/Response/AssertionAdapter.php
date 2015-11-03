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
     * @var ParameterBag
     */
    private $assertionAttributes;

    /**
     * @var \Surfnet\SamlBundle\SAML2\Attribute\AttributeDictionary
     */
    private $attributeDictionary;

    public function __construct(SAML2_Assertion $assertion, AttributeDictionary $attributes)
    {
        $this->assertion = $assertion;
        $this->assertionAttributes = new ParameterBag($assertion->getAttributes());
        $this->attributeDictionary = $attributes;
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
     * @param string $name
     * @param null   $default
     * @return mixed|null
     */
    public function getAttribute($name, $default = null)
    {
        $attributeDefinition = $this->attributeDictionary->getAttributeDefinition($name);

        // try first by urn:mace, then by urn:oid
        if ($this->assertionAttributes->has($attributeDefinition->getUrnMace())) {
            $attribute = $this->assertionAttributes->get($attributeDefinition->getUrnMace());
        } elseif ($this->assertionAttributes->has($attributeDefinition->getUrnOid())) {
            $attribute = $this->assertionAttributes->get($attributeDefinition->getUrnOid());
        } else {
            return $default;
        }

        // if it is singular, it should return the single value if it has a value
        if ($attributeDefinition->getMultiplicity() === AttributeDefinition::MULTIPLICITY_SINGLE) {
            $count = count($attribute);
            if ($count > 1) {
                throw new UnexpectedValueException(sprintf(
                    'AttributeDefinition "%s" has a single-value multiplicity, yet returned'
                    . ' "%d" values',
                    $attributeDefinition->getName(),
                    count($attribute)
                ));
            } elseif ($count === 0) {
                $attribute = null;
            } else {
                $attribute = reset($attribute);
            }
        }

        return $attribute;
    }

    /**
     * @return AttributeSet
     */
    public function getAttributeSet()
    {
        $attributeSet = new AttributeSet();

        foreach ($this->assertionAttributes->all() as $urn => $value) {
            $definition = $this->attributeDictionary->findAttributeDefinitionByUrn($urn);

            if ($definition && !$attributeSet->containsDefinition($definition)) {
                $attributeSet->add(new Attribute($definition, $value));
            }
        }

        return $attributeSet;
    }
}
