<?php declare(strict_types=1);

/**
 * Copyright 2023 SURFnet B.V.
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

namespace Surfnet\SamlBundle\Security\Authentication\Passport\Badge;

use SAML2\XML\saml\NameID;
use Symfony\Component\Security\Http\Authenticator\Passport\Badge\BadgeInterface;

class SamlAttributesBadge implements BadgeInterface
{
    private readonly array $attributes;
    public function __construct(array $attributes)
    {
        foreach ($attributes as $key => $attributeParts) {
            foreach ($attributeParts as $index => $attribute) {
                // NameID can not be serialized, resulting in a 500 error during authentication
                if ($attribute instanceof NameID) {
                    $attributes[$key][$index] = [
                        'Value' => $attribute->getValue(),
                        'Format' => $attribute->getFormat()
                    ];
                }
            }
        }
        $this->attributes = $attributes;
    }

    public function getAttributes(): array
    {
        return $this->attributes;
    }

    public function isResolved(): bool
    {
        return true;
    }
}
