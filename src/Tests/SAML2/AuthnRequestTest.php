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

namespace Surfnet\SamlBundle\Tests\SAML2;

use PHPUnit_Framework_TestCase as UnitTest;
use SAML2_AuthnRequest;
use SAML2_DOMDocumentFactory;
use Surfnet\SamlBundle\SAML2\AuthnRequest;

class AuthnRequestTest extends UnitTest
{
    /**
     * @var string
     */
    private $authRequestWithSubject = <<<AUTHNREQUEST_WITH_SUBJECT
<samlp:AuthnRequest
    xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
    xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
    AssertionConsumerServiceIndex="1"
    Destination="https://tiqr.stepup.org/idp/profile/saml2/Redirect/SSO"
    ID="_2b0226190ca1c22de6f66e85f5c95158"
    IssueInstant="2014-09-22T13:42:00Z"
    Version="2.0">
  <saml:Issuer>https://gateway.stepup.org/saml20/sp/metadata</saml:Issuer>
  <saml:Subject>
        <saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified">user@example.org</saml:NameID>
  </saml:Subject>
</samlp:AuthnRequest>
AUTHNREQUEST_WITH_SUBJECT;

    /**
     * @var string
     */
    private $authRequestNoSubject = <<<AUTHNREQUEST_NO_SUBJECT
<samlp:AuthnRequest
    xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
    xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
    AssertionConsumerServiceIndex="1"
    Destination="https://tiqr.stepup.org/idp/profile/saml2/Redirect/SSO"
    ID="_2b0226190ca1c22de6f66e85f5c95158"
    IssueInstant="2014-09-22T13:42:00Z"
    Version="2.0">
  <saml:Issuer>https://gateway.stepup.org/saml20/sp/metadata</saml:Issuer>
</samlp:AuthnRequest>
AUTHNREQUEST_NO_SUBJECT;

    /**
     * @var string
     */
    private $nameId = 'user@example.org';

    /**
     * @var string
     */
    private $format = 'urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified';

    /**
     * @test
     * @group saml2
     * @dataProvider provideNameIDAndFormatCombinations
     *
     * @param $nameId
     * @param $format
     */
    public function setting_the_subject_generates_valid_xml($nameId, $format)
    {
        $domDocument = SAML2_DOMDocumentFactory::fromString($this->authRequestNoSubject);
        $request     = new SAML2_AuthnRequest($domDocument->documentElement);

        $authnRequest = AuthnRequest::createNew($request);
        $authnRequest->setSubject($nameId, $format);

        $this->assertXmlStringEqualsXmlString($this->authRequestWithSubject, $authnRequest->getUnsignedXML());
    }

    /**
     * @test
     * @group saml2
     */
    public function the_nameid_and_format_can_be_retrieved_from_the_authnrequest()
    {
        $domDocument = SAML2_DOMDocumentFactory::fromString($this->authRequestWithSubject);
        $request     = new SAML2_AuthnRequest($domDocument->documentElement);

        $authnRequest = AuthnRequest::createNew($request);

        $this->assertEquals($this->nameId, $authnRequest->getNameId());
        $this->assertEquals($this->format, $authnRequest->getNameIdFormat());
    }

    public function provideNameIDAndFormatCombinations()
    {
        return [
            'NameID without Format' => [$this->nameId, null],
            'NameID with Format'    => [$this->nameId, $this->format]
        ];
    }
}
