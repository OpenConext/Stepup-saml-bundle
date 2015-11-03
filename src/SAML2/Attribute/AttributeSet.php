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
use Serializable;

class AttributeSet implements IteratorAggregate, Countable, Serializable
{
    /**
     * @var Attribute[]
     */
    private $attributes = [];

    /**
     * @param Attribute $attribute
     */
    public function add(Attribute $attribute)
    {
        if (!$this->contains($attribute)) {
            $this->attributes[] = $attribute;
        }
    }

    /**
     * @param AttributeDefinition $otherAttributeDefinition
     * @return bool
     */
    public function containsDefinition(AttributeDefinition $otherAttributeDefinition)
    {
        foreach ($this->attributes as $attribute) {
            if ($attribute->getAttributeDefinition()->equals($otherAttributeDefinition)) {
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

    public function serialize()
    {
        return serialize($this->attributes);
    }

    public function unserialize($serialized)
    {
        $this->attributes = unserialize($serialized);
    }
}
