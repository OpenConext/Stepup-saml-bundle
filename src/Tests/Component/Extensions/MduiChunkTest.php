<?php declare(strict_types=1);

/**
 * Copyright 2026 SURFnet bv
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
use RuntimeException;
use Surfnet\SamlBundle\SAML2\Extensions\MduiChunk;

class MduiChunkTest extends TestCase
{
    public function test_mdui_chunk_round_trips_display_names_through_xml(): void
    {
        $xml = '<mdui:UIInfo xmlns:mdui="urn:oasis:names:tc:SAML:metadata:ui">'
            . '<mdui:DisplayName xml:lang="en">My Service</mdui:DisplayName>'
            . '<mdui:DisplayName xml:lang="nl">Mijn Dienst</mdui:DisplayName>'
            . '</mdui:UIInfo>';

        $chunk = MduiChunk::fromXML($xml);
        $restored = MduiChunk::fromXML($chunk->toXML());

        $this->assertSame(
            ['en' => 'My Service', 'nl' => 'Mijn Dienst'],
            $restored->getDisplayNames()
        );
    }

    public function test_from_xml_throws_on_malformed_xml(): void
    {
        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('Unable to parse UIInfo XML');

        MduiChunk::fromXML('<mdui:UIInfo unclosed');
    }
}
