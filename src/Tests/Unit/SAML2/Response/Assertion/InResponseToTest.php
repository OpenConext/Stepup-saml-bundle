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

namespace Surfnet\SamlBundle\Tests\Unit\SAML2\Response\Assertion;

use PHPUnit\Framework\TestCase;
use SAML2\Assertion;
use SAML2\Compat\ContainerSingleton;
use SAML2\Compat\MockContainer;
use SAML2\XML\saml\SubjectConfirmation;
use SAML2\XML\saml\SubjectConfirmationData;
use Surfnet\SamlBundle\SAML2\Response\Assertion\InResponseTo;

class InResponseToTest extends TestCase
{

    /**
     * @test
     * @group saml2-response
     * @group saml2
     * @dataProvider provideAssertionsWithoutInResponseTo
     */
    public function assertions_without_in_response_to_are_tested_as_if_in_response_to_is_null(Assertion $assertion): void
    {
        $this->assertTrue(InResponseTo::assertEquals($assertion, null));
        $this->assertFalse(InResponseTo::assertEquals($assertion, 'some not-null-value'));
    }

    /**
     * @test
     * @group saml2-response
     * @group saml2
     */
    public function in_reponse_to_equality_is_strictly_checked(): void
    {
        $assertion                   = new Assertion();
        $subjectConfirmationWithData = new SubjectConfirmation();
        $subjectConfirmationData     = new SubjectConfirmationData();
        $subjectConfirmationData->setInResponseTo('1');
        $subjectConfirmationWithData->setSubjectConfirmationData($subjectConfirmationData);
        $assertion->setSubjectConfirmation([$subjectConfirmationWithData]);

        $this->assertTrue(InResponseTo::assertEquals($assertion, '1'));
        $this->assertFalse(InResponseTo::assertEquals($assertion, 1));
    }

    public function provideAssertionsWithoutInResponseTo(): array
    {
        ContainerSingleton::setContainer(new MockContainer());
        $assertionWithoutSubjectConfirmation = new Assertion();

        $assertionWithoutSubjectConfirmationData = new Assertion();
        $subjectConfirmation = new SubjectConfirmation();
        $assertionWithoutSubjectConfirmationData->setSubjectConfirmation([$subjectConfirmation]);

        $assertionWithEmptyInResponseTo = new Assertion();
        $subjectConfirmationWithData = new SubjectConfirmation();
        $subjectConfirmationWithData->setSubjectConfirmationData(new SubjectConfirmationData());
        $assertionWithEmptyInResponseTo->setSubjectConfirmation([$subjectConfirmationWithData]);

        return [
            'No Subject Confirmation'      => [$assertionWithoutSubjectConfirmation],
            'No Subject Confirmation Data' => [$assertionWithoutSubjectConfirmationData],
            'Empty In Reponse To'          => [$assertionWithEmptyInResponseTo]
        ];
    }
}
