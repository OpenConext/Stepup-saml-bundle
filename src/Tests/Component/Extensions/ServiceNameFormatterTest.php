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
use Surfnet\SamlBundle\SAML2\Extensions\ServiceNameFormatter;

class ServiceNameFormatterTest extends TestCase
{
    public function test_it_leaves_a_short_value_unchanged(): void
    {
        $this->assertSame('My Service', ServiceNameFormatter::format('My Service'));
    }

    public function test_it_truncates_to_39_characters_and_appends_an_ellipsis(): void
    {
        $value = str_repeat('A', 50);

        $result = ServiceNameFormatter::format($value);

        $this->assertSame(str_repeat('A', 39) . "\u{2026}", $result);
        $this->assertSame(40, mb_strlen($result));
    }

    public function test_it_trims_and_collapses_whitespace(): void
    {
        $this->assertSame('My Service', ServiceNameFormatter::format("  My   \tService\n "));
    }

    public function test_it_strips_control_and_format_characters(): void
    {
        $this->assertSame('My Service', ServiceNameFormatter::format("My\x01 Service"));
    }

    public function test_sanitize_lang_strips_control_and_format_characters(): void
    {
        $this->assertSame('en', ServiceNameFormatter::sanitizeLang("e\x01n"));
    }

    public function test_sanitize_lang_leaves_a_clean_value_unchanged(): void
    {
        $this->assertSame('en-GB', ServiceNameFormatter::sanitizeLang('en-GB'));
    }
}
