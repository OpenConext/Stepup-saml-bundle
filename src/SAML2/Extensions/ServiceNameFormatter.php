<?php

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

namespace Surfnet\SamlBundle\SAML2\Extensions;

/**
 * Sanitizes an mdui:DisplayName value (and its xml:lang attribute) per the
 * "Showing Service name during authentication" RFC (OpenConext/Stepup-Gateway#587):
 * the name is forwarded into SMS/push notifications with much tighter limits than
 * SAML 2.0's own string bounds, so it's truncated, whitespace-normalized, and
 * stripped of control/format characters before being used anywhere.
 *
 * This is the single, canonical implementation: it previously existed as separate,
 * independently-drifting copies in Stepup-Gateway, Stepup-gssp-bundle, and Stepup-Webauthn
 * (one of which had an off-by-one truncation bug the others didn't).
 */
final class ServiceNameFormatter
{
    private const MAX_CHARACTERS = 40;
    private const TRUNCATION_SUFFIX = "\u{2026}";

    public static function format(string $raw): string
    {
        $value = preg_replace('/[\p{Cc}\p{Cf}]/u', '', $raw) ?? $raw;
        $value = preg_replace('/\s+/u', ' ', $value) ?? $value;
        $value = trim($value);

        if (mb_strlen($value) > self::MAX_CHARACTERS) {
            $value = mb_substr($value, 0, self::MAX_CHARACTERS - 1) . self::TRUNCATION_SUFFIX;
        }

        return $value;
    }

    // xml:lang has no length/whitespace rules to apply, but still needs control/format
    // characters stripped before it lands in an outgoing attribute.
    public static function sanitizeLang(string $lang): string
    {
        return preg_replace('/[\p{Cc}\p{Cf}]/u', '', $lang) ?? $lang;
    }
}
