<?php

namespace Surfnet\SamlBundle\SAML2\Attribute;

class Attribute
{
    /**
     * @var string
     */
    private $name;

    /**
     * @var array
     */
    private $values;

    /**
     * @var string
     */
    private $urnMace;

    /**
     * @var string
     */
    private $urnOid;

    /**
     * @param AttributeDefinition $definition
     * @param array $values
     */
    public function __construct(AttributeDefinition $definition, array $values)
    {
        $this->name = $definition->getName();
        $this->urnMace = $definition->getUrnMace();
        $this->urnOid = $definition->getUrnOid();
        $this->values = $values;
    }

    /**
     * @return string
     */
    public function getName()
    {
        return $this->name;
    }

    /**
     * @return string
     */
    public function getUrnMace()
    {
        return $this->urnMace;
    }

    /**
     * @return string
     */
    public function getUrnOid()
    {
        return $this->urnOid;
    }

    /**
     * @return string
     */
    public function getValues()
    {
        return $this->values;
    }

    /**
     * @param Attribute $attribute
     * @return bool
     */
    public function equals(Attribute $attribute)
    {
        return $attribute == $this;
    }
}
