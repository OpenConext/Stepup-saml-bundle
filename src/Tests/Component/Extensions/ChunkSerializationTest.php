<?php declare(strict_types=1);

/**
 * Copyright 2025 SURFnet bv
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

namespace Surfnet\SamlBundle\Tests\Component\Extensions;

use PHPUnit\Framework\TestCase;
use Surfnet\SamlBundle\SAML2\Extensions\GsspUserAttributesChunk;

class ChunkSerializationTest extends TestCase
{

    public function test_gsspchunk_is_serializable(): void
    {
        $chunk = new GsspUserAttributesChunk();
        $chunk->addAttribute(
            'urn:mace:dir:attribute-def:mail',
            'urn:oasis:names:tc:SAML:2.0:attrname-format:uri',
            'test@test.nl'
        );
        $chunk->addAttribute(
            'urn:mace:dir:attribute-def:surname',
            'urn:oasis:names:tc:SAML:2.0:attrname-format:string',
            'Doe 1'
        );

        $xmlString = $chunk->toXML();

        $newChunk = GsspUserAttributesChunk::fromXML($xmlString);

        self::assertEquals($chunk->getName(), $newChunk->getName());
        self::assertEquals($chunk->getNamespace(), $newChunk->getNamespace());
        self::assertEquals($chunk->getAttributeValue('urn:mace:dir:attribute-def:mail'), $newChunk->getAttributeValue('urn:mace:dir:attribute-def:mail'));
    }
}
