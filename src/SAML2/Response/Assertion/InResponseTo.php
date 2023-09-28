<?php declare(strict_types=1);

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

namespace Surfnet\SamlBundle\SAML2\Response\Assertion;

use SAML2\Assertion;

class InResponseTo
{
    public static function assertEquals(Assertion $assertion, mixed $inResponseTo): bool
    {
        $assertionInResponseTo = static::getInResponseTo($assertion);

        return $assertionInResponseTo === $inResponseTo;
    }

    private static function getInResponseTo(Assertion $assertion): ?string
    {
        $subjectConfirmationArray = $assertion->getSubjectConfirmation();

        if ($subjectConfirmationArray === []) {
            return null;
        }

        $subjectConfirmation = $subjectConfirmationArray[0];
        return $subjectConfirmation->getSubjectConfirmationData()?->getInResponseTo();
    }
}
