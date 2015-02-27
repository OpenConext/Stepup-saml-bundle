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

namespace Surfnet\SamlBundle\Tests\SAML2\Response\Validator;

use PHPUnit_Framework_TestCase as UnitTest;
use SAML2_Assertion;
use SAML2_XML_saml_SubjectConfirmation;
use SAML2_XML_saml_SubjectConfirmationData;
use Surfnet\SamlBundle\SAML2\Response\Assertion\InResponseTo;

class InResponseToTest extends UnitTest
{
    /**
     * @param SAML2_Assertion $assertion
     *
     * @test
     * @group saml2-response
     * @dataProvider provideAssertionsWithoutInResponseTo
     */
    public function assertions_without_in_response_to_are_tested_as_if_in_response_to_is_null(SAML2_Assertion $assertion)
    {
        $this->assertTrue(InResponseTo::assertEquals($assertion, null));
        $this->assertFalse(InResponseTo::assertEquals($assertion, 'some not-null-value'));
    }

    /**
     * @test
     * @group saml2-response
     */
    public function in_reponse_to_equality_is_strictly_checked()
    {
        $assertion                   = new SAML2_Assertion();
        $subjectConfirmationWithData = new SAML2_XML_saml_SubjectConfirmation();
        $subjectConfirmationData     = new SAML2_XML_saml_SubjectConfirmationData();
        $subjectConfirmationData->InResponseTo = '1';
        $subjectConfirmationWithData->SubjectConfirmationData = $subjectConfirmationData;
        $assertion->setSubjectConfirmation([$subjectConfirmationWithData]);

        $this->assertTrue(InResponseTo::assertEquals($assertion, '1'));
        $this->assertFalse(InResponseTo::assertEquals($assertion, 1));
    }

    /**
     * @return array
     */
    public function provideAssertionsWithoutInResponseTo()
    {
        $assertionWithoutSubjectConfirmation = new SAML2_Assertion();

        $assertionWithoutSubjectConfirmationData = new SAML2_Assertion();
        $subjectConfirmation = new SAML2_XML_saml_SubjectConfirmation();
        $assertionWithoutSubjectConfirmationData->setSubjectConfirmation([$subjectConfirmation]);

        $assertionWithEmptyInResponseTo = new SAML2_Assertion();
        $subjectConfirmationWithData = new SAML2_XML_saml_SubjectConfirmation();
        $subjectConfirmationWithData->SubjectConfirmationData = new SAML2_XML_saml_SubjectConfirmationData();
        $assertionWithEmptyInResponseTo->setSubjectConfirmation([$subjectConfirmationWithData]);

        return [
            'No Subject Confirmation'      => [$assertionWithoutSubjectConfirmation],
            'No Subject Confirmation Data' => [$assertionWithoutSubjectConfirmationData],
            'Empty In Reponse To'          => [$assertionWithEmptyInResponseTo]
        ];
    }
}
