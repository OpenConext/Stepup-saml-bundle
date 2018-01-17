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

namespace Surfnet\SamlBundle\SAML2\Response\Assertion;

use SAML2\Assertion;

class InResponseTo
{
    /**
     * @param Assertion $assertion
     * @param string    $inResponseTo
     * @return bool
     */
    public static function assertEquals(Assertion $assertion, $inResponseTo)
    {
        $assertionInResponseTo = static::getInResponseTo($assertion);

        return $assertionInResponseTo === $inResponseTo;
    }

    /**
     * @param Assertion $assertion
     * @return null|string
     */
    private static function getInResponseTo(Assertion $assertion)
    {
        $subjectConfirmationArray = $assertion->getSubjectConfirmation();

        if (empty($subjectConfirmationArray)) {
            return null;
        }

        /** @var \SAML2\XML\saml\SubjectConfirmation $subjectConfirmation */
        $subjectConfirmation = $subjectConfirmationArray[0];
        if (!$subjectConfirmation->SubjectConfirmationData) {
            return null;
        }

        return $subjectConfirmation->SubjectConfirmationData->InResponseTo;
    }
}
