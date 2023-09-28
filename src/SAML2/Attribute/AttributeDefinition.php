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
    private readonly string $name;

    /**
     * @var string the urn:mace identifier of this attribute
     */
    private ?string $urnMace = null;

    /**
     * @var string the urn:oid identifier of this attribute
     */
    private ?string $urnOid = null;

    public function __construct(string $name, ?string $urnMace = null, ?string $urnOid = null)
    {
        if (is_null($urnOid) && is_null($urnMace)) {
            throw new LogicException('An AttributeDefinition should have at least either a mace or an oid urn');
        }

        $this->name         = $name;
        $this->urnMace      = $urnMace;
        $this->urnOid       = $urnOid;
    }

    public function getName(): string
    {
        return $this->name;
    }

    public function hasUrnMace(): bool
    {
        return $this->urnMace !== null;
    }

    public function getUrnMace(): ?string
    {
        return $this->urnMace;
    }

    public function hasUrnOid(): bool
    {
        return $this->urnOid !== null;
    }

    public function getUrnOid(): ?string
    {
        return $this->urnOid;
    }

    public function equals(AttributeDefinition $other): bool
    {
        return $this->name === $other->name
            && $this->urnOid === $other->urnOid
            && $this->urnMace === $other->urnMace;
    }
}
