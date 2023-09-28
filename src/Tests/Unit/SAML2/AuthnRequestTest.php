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

namespace Surfnet\SamlBundle\Tests\Unit\SAML2;

use PHPUnit\Framework\TestCase;
use SAML2\AuthnRequest as SAML2AuthnRequest;
use SAML2\DOMDocumentFactory;
use SAML2\XML\saml\NameID;
use Surfnet\SamlBundle\SAML2\AuthnRequest;

class AuthnRequestTest extends TestCase
{
    private string $authRequestWithSubject = <<<AUTHNREQUEST_WITH_SUBJECT
<samlp:AuthnRequest
    xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
    xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
    AssertionConsumerServiceURL="https://example.org"
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

    private string $authRequestNoSubject = <<<AUTHNREQUEST_NO_SUBJECT
<samlp:AuthnRequest
    xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
    xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
    AssertionConsumerServiceURL="https://example.org"
    Destination="https://tiqr.stepup.org/idp/profile/saml2/Redirect/SSO"
    ID="_2b0226190ca1c22de6f66e85f5c95158"
    IssueInstant="2014-09-22T13:42:00Z"
    Version="2.0">
  <saml:Issuer>https://gateway.stepup.org/saml20/sp/metadata</saml:Issuer>
</samlp:AuthnRequest>
AUTHNREQUEST_NO_SUBJECT;

    private string $authRequestIsPassiveFalseAndNoForceAuthnFalse = <<<AUTHNREQUEST_IS_PASSIVE_F_AND_FORCE_AUTH_F
<samlp:AuthnRequest
    xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
    xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
    AssertionConsumerServiceURL="https://example.org"
    Destination="https://tiqr.stepup.org/idp/profile/saml2/Redirect/SSO"
    ID="_2b0226190ca1c22de6f66e85f5c95158"
    IssueInstant="2014-09-22T13:42:00Z"
    Version="2.0">
  <saml:Issuer>https://gateway.stepup.org/saml20/sp/metadata</saml:Issuer>
</samlp:AuthnRequest>
AUTHNREQUEST_IS_PASSIVE_F_AND_FORCE_AUTH_F;

    private string $authRequestIsPassiveAndForceAuthnFalse = <<<AUTHNREQUEST_IS_PASSIVE_AND_FORCE_AUTHN_F
<samlp:AuthnRequest
    xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
    xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
    AssertionConsumerServiceURL="https://example.org"
    Destination="https://tiqr.stepup.org/idp/profile/saml2/Redirect/SSO"
    ID="_2b0226190ca1c22de6f66e85f5c95158"
    IssueInstant="2014-09-22T13:42:00Z"
    Version="2.0"
    IsPassive="true">
  <saml:Issuer>https://gateway.stepup.org/saml20/sp/metadata</saml:Issuer>
</samlp:AuthnRequest>
AUTHNREQUEST_IS_PASSIVE_AND_FORCE_AUTHN_F;

    private string $authRequestIsPassiveFalseAndForceAuthn = <<<AUTHNREQUEST_IS_PASSIVE_F_AND_FORCE_AUTHN
<samlp:AuthnRequest
    xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
    xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
    AssertionConsumerServiceURL="https://example.org"
    Destination="https://tiqr.stepup.org/idp/profile/saml2/Redirect/SSO"
    ID="_2b0226190ca1c22de6f66e85f5c95158"
    IssueInstant="2014-09-22T13:42:00Z"
    Version="2.0"
    ForceAuthn="true">
  <saml:Issuer>https://gateway.stepup.org/saml20/sp/metadata</saml:Issuer>
</samlp:AuthnRequest>
AUTHNREQUEST_IS_PASSIVE_F_AND_FORCE_AUTHN;

    private string $acsUrl = 'https://example.org';

    /**
     * @test
     * @group saml2
     * @dataProvider provideNameIDAndFormatCombinations
     */
    public function setting_the_subject_generates_valid_xml(string $nameId, ?string $format): void
    {
        $domDocument = DOMDocumentFactory::fromString($this->authRequestNoSubject);
        $request     = new SAML2AuthnRequest($domDocument->documentElement);

        $authnRequest = AuthnRequest::createNew($request);
        $authnRequest->setSubject($nameId, $format);

        $this->assertXmlStringEqualsXmlString($this->authRequestWithSubject, $authnRequest->getUnsignedXML());
    }

    /**
     * @test
     * @group saml2
     */
    public function the_nameid_and_format_can_be_retrieved_from_the_authnrequest(): void
    {
        $domDocument = DOMDocumentFactory::fromString($this->authRequestWithSubject);
        $request     = new SAML2AuthnRequest($domDocument->documentElement);

        $authnRequest = AuthnRequest::createNew($request);

        $nameId = new NameID();
        $nameId->setValue('user@example.org');
        $nameId->setFormat('urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified');

        $this->assertEquals($nameId->getValue(), $authnRequest->getNameId());
        $this->assertEquals($nameId->getFormat(), $authnRequest->getNameIdFormat());
    }

    /**
     * @test
     * @group saml2
     */
    public function the_acs_url_can_be_retrieved_from_the_authnrequest(): void
    {
        $domDocument = DOMDocumentFactory::fromString($this->authRequestWithSubject);
        $request     = new SAML2AuthnRequest($domDocument->documentElement);

        $authnRequest = AuthnRequest::createNew($request);

        $this->assertEquals($this->acsUrl, $authnRequest->getAssertionConsumerServiceURL());
    }

    /**
     * @test
     * @group saml2
     * @dataProvider provideIsPassiveAndForceAuthnCombinations
     */
    public function is_passive_and_force_authn_can_be_retrieved_from_the_authnrequest(string $xml, bool $isPassive, bool $forceAuthn): void
    {
        $domDocument = DOMDocumentFactory::fromString($xml);
        $request     = new SAML2AuthnRequest($domDocument->documentElement);
        $authnRequest = AuthnRequest::createNew($request);

        $this->assertEquals($isPassive, $authnRequest->isPassive());
        $this->assertEquals($forceAuthn, $authnRequest->isForceAuthn());
    }

    public function provideIsPassiveAndForceAuthnCombinations(): array
    {
        return [
            'isPassive false and ForceAuthn false' => [$this->authRequestIsPassiveFalseAndNoForceAuthnFalse, false, false],
            'isPassive and ForceAuthn false' => [$this->authRequestIsPassiveAndForceAuthnFalse, true, false],
            'isPassive false and ForceAuthn' => [$this->authRequestIsPassiveFalseAndForceAuthn, false, true]
        ];
    }

    public function provideNameIDAndFormatCombinations(): array
    {
        $nameId = new NameID();
        $nameId->setValue('user@example.org');
        $nameId->setFormat('urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified');

        return [
            'NameID without Format' => [$nameId->getValue(), null],
            'NameID with Format'    => [$nameId->getValue(), $nameId->getFormat()]
        ];
    }
}
