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

use Surfnet\SamlBundle\Exception\InvalidArgumentException;
use Surfnet\SamlBundle\Exception\LogicException;

class AttributeDefinition
{
    /**
     * @var string the name of the saml attribute
     */
    private $name;

    /**
     * @var string the urn:mace identifier of this attribute
     */
    private $urnMace;

    /**
     * @var string the urn:oid identifier of this attribute
     */
    private $urnOid;

    /**
     * @param string $name
     * @param string $urnMace
     * @param string $urnOid
     */
    public function __construct($name, $urnMace = null, $urnOid = null)
    {
        if (!is_string($name)) {
            throw InvalidArgumentException::invalidType('string', 'name', $name);
        }

        if (!is_null($urnMace) && !is_string($urnMace)) {
            throw InvalidArgumentException::invalidType('null or string', 'urnMace', $urnMace);
        }

        if (!is_null($urnOid) && !is_string($urnOid)) {
            throw InvalidArgumentException::invalidType('null or string', 'urnOid', $urnOid);
        }

        if (is_null($urnOid) && is_null($urnMace)) {
            throw new LogicException('An AttributeDefinition should have at least either a mace or an oid urn');
        }

        $this->name         = $name;
        $this->urnMace      = $urnMace;
        $this->urnOid       = $urnOid;
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
    public function hasUrnMace()
    {
        return $this->urnMace !== null;
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
    public function hasUrnOid()
    {
        return $this->urnOid !== null;
    }

    /**
     * @return string
     */
    public function getUrnOid()
    {
        return $this->urnOid;
    }

    /**
     * @param AttributeDefinition $other
     * @return bool
     */
    public function equals(AttributeDefinition $other)
    {
        return $this->name === $other->name
            && $this->urnOid === $other->urnOid
            && $this->urnMace === $other->urnMace;
    }
}
