<?php declare(strict_types=1);

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

use SAML2\Assertion;
use Surfnet\SamlBundle\SAML2\Attribute\AttributeDictionary;
use Surfnet\SamlBundle\SAML2\Attribute\AttributeSetInterface;
use Surfnet\SamlBundle\SAML2\Attribute\ConfigurableAttributeSetFactory;

class AssertionAdapter
{
    private readonly AttributeSetInterface $attributeSet;

    private readonly AttributeDictionary $attributeDictionary;

    public function __construct(private readonly Assertion $assertion, AttributeDictionary $attributeDictionary)
    {
        $this->attributeSet = ConfigurableAttributeSetFactory::createFrom($assertion, $attributeDictionary);
        $this->attributeDictionary = $attributeDictionary;
    }

    /**
     * @return string
     */
    public function getNameID(): ?string
    {
        $data = $this->assertion->getNameId();
        if ($data instanceof \SAML2\XML\saml\NameID) {
            return $data->getValue();
        }

        return null;
    }

    /**
     * @param string $attributeName the name of the attribute to attempt to get the value of
     * @param mixed  $defaultValue  the value to return should the assertion not contain the attribute
     * @return string[]|mixed string[] if the attribute is found, the given default value otherwise
     */
    public function getAttributeValue($attributeName, mixed $defaultValue = null): mixed
    {
        $attributeDefinition = $this->attributeDictionary->getAttributeDefinition($attributeName);

        if (!$this->attributeSet->containsAttributeDefinedBy($attributeDefinition)) {
            return $defaultValue;
        }

        $attribute = $this->attributeSet->getAttributeByDefinition($attributeDefinition);

        return $attribute->getValue();
    }

    /**
     * @return AttributeSetInterface
     */
    public function getAttributeSet(): AttributeSetInterface
    {
        return $this->attributeSet;
    }
}
