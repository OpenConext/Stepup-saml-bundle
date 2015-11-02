<?php

namespace Surfnet\SamlBundle\SAML2\Attribute;

use ArrayIterator;
use Countable;
use IteratorAggregate;

class AttributeSet implements IteratorAggregate, Countable
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

    /**
     * @return ArrayIterator
     */
    public function getIterator()
    {
        return new ArrayIterator($this->attributes);
    }

    /**
     * @return int
     */
    public function count()
    {
        return sizeof($this->attributes);
    }
}
