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

namespace Surfnet\SamlBundle\Tests\Http;

use Mockery as m;
use Mockery\Adapter\Phpunit\MockeryPHPUnitIntegration;
use PHPUnit\Framework\TestCase;
use SAML2\Assertion;
use SAML2\Compat\ContainerSingleton;
use SAML2\Compat\MockContainer;
use SAML2\Response\Exception\PreconditionNotMetException;
use SAML2\Response\Processor;
use SAML2\Utilities\ArrayCollection;
use Surfnet\SamlBundle\Entity\IdentityProvider;
use Surfnet\SamlBundle\Entity\ServiceProvider;
use Surfnet\SamlBundle\Entity\ServiceProviderRepository;
use Surfnet\SamlBundle\Http\Exception\AuthnFailedSamlResponseException;
use Surfnet\SamlBundle\Http\Exception\NoAuthnContextSamlResponseException;
use Surfnet\SamlBundle\Http\PostBinding;
use Surfnet\SamlBundle\Signing\SignatureVerifier;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpKernel\Exception\BadRequestHttpException;

class PostBindingSamlResponseTest extends TestCase
{
    use MockeryPHPUnitIntegration;

    const RAW_MESSAGE = <<<MESSAGE
<?xml version="1.0"?>
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_8e8dc5f69a98cc4c1ff3427e5ce34606fd672f91e6" Version="2.0" IssueInstant="2014-07-17T01:01:48Z" Destination="http://sp.example.com/demo1/index.php?acs" InResponseTo="ONELOGIN_4fee3b046395c4e751011e97f8900b5273d56685"><saml:Issuer>http://idp.example.com/metadata.php</saml:Issuer><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status><saml:Assertion xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xs="http://www.w3.org/2001/XMLSchema" ID="_d71a3a8e9fcc45c9e9d248ef7049393fc8f04e5f75" Version="2.0" IssueInstant="2014-07-17T01:01:48Z"><saml:Issuer>http://idp.example.com/metadata.php</saml:Issuer><saml:Subject><saml:NameID SPNameQualifier="http://sp.example.com/demo1/metadata.php" Format="urn:oasis:names:tc:SAML:2.0:nameid-format:transient">_ce3d2948b4cf20146dee0a0b3dd6f69b6cf86f62d7</saml:NameID><saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml:SubjectConfirmationData NotOnOrAfter="2024-01-18T06:21:48Z" Recipient="http://sp.example.com/demo1/index.php?acs" InResponseTo="ONELOGIN_4fee3b046395c4e751011e97f8900b5273d56685"/></saml:SubjectConfirmation></saml:Subject><saml:Conditions NotBefore="2014-07-17T01:01:18Z" NotOnOrAfter="2024-01-18T06:21:48Z"><saml:AudienceRestriction><saml:Audience>http://sp.example.com/demo1/metadata.php</saml:Audience></saml:AudienceRestriction></saml:Conditions><saml:AuthnStatement AuthnInstant="2014-07-17T01:01:48Z" SessionNotOnOrAfter="2024-07-17T09:01:48Z" SessionIndex="_be9967abd904ddcae3c0eb4189adbe3f71e327cf93"><saml:AuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:Password</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement><saml:AttributeStatement><saml:Attribute Name="uid" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"><saml:AttributeValue xsi:type="xs:string">test</saml:AttributeValue></saml:Attribute><saml:Attribute Name="mail" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"><saml:AttributeValue xsi:type="xs:string">test@example.com</saml:AttributeValue></saml:Attribute><saml:Attribute Name="eduPersonAffiliation" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"><saml:AttributeValue xsi:type="xs:string">users</saml:AttributeValue><saml:AttributeValue xsi:type="xs:string">examplerole1</saml:AttributeValue></saml:Attribute></saml:AttributeStatement></saml:Assertion></samlp:Response>

MESSAGE;

    private PostBinding $postBinding;

    private m\MockInterface&ServiceProviderRepository $entityRepository;

    private m\MockInterface&SignatureVerifier $signatureVerifier;

    private m\MockInterface&Processor $processor;

    public function setUp(): void
    {
        $this->processor = m::mock(Processor::class);
        $this->entityRepository = m::mock(ServiceProviderRepository::class);
        $this->signatureVerifier = m::mock(SignatureVerifier::class);

        $this->postBinding = new PostBinding(
            $this->processor,
            $this->signatureVerifier,
            $this->entityRepository
        );
        ContainerSingleton::setContainer(new MockContainer());
    }

    private function buildRequest(): Request
    {
        $requestUri = 'https://stepup.example.com/';
        $post = [
            'SAMLResponse' => base64_encode(self::RAW_MESSAGE),
            'RelayState' => '',
        ];
        return new Request([], $post, [], [], [], ['REQUEST_URI' => $requestUri]);
    }

    public function test_process_response_happy_flow()
    {
        $request = $this->buildRequest();
        $request->setMethod(Request::METHOD_POST);
        $idp = m::mock(IdentityProvider::class);
        $sp = m::mock(ServiceProvider::class);
        $sp
            ->shouldReceive('getAssertionConsumerUrl')
            ->andReturn('https://stepup.example.com/acs')
        ;
        $assertions = m::mock(ArrayCollection::class);
        $assertions->shouldReceive('getOnlyElement')->andReturn(m::mock(Assertion::class));
        $this->processor->shouldReceive('process')->andReturn($assertions);
        $samlResponse = $this->postBinding->processResponse($request, $idp, $sp);

        self::assertInstanceOf(Assertion::class, $samlResponse);
    }

    public function test_process_response_must_have_saml_response()
    {
        $requestUri = 'https://stepup.example.com/';
        $post = [
            // Note we post a SAMLRequest here
            'SAMLRequest' => base64_encode(self::RAW_MESSAGE),
        ];
        $request = new Request([], $post, [], [], [], ['REQUEST_URI' => $requestUri]);
        $request->setMethod(Request::METHOD_POST);
        $idp = m::mock(IdentityProvider::class);
        $sp = m::mock(ServiceProvider::class);

        self::expectException(BadRequestHttpException::class);
        self::expectExceptionMessage('Response must include a SAMLResponse, none found');
        $this->postBinding->processResponse($request, $idp, $sp);
    }

    public function test_process_response_precondition_not_met()
    {
        $request = $this->buildRequest();

        $request->setMethod(Request::METHOD_POST);
        $idp = m::mock(IdentityProvider::class);
        $sp = m::mock(ServiceProvider::class);
        $sp
            ->shouldReceive('getAssertionConsumerUrl')
            ->andReturn('https://stepup.example.com/acs');
        $assertions = m::mock(ArrayCollection::class);
        $assertions->shouldReceive('getOnlyElement')->andReturn(m::mock(Assertion::class));
        $this->processor->shouldReceive('process')->andThrow(new PreconditionNotMetException('urn:oasis:names:tc:SAML:2.0:status:NoAuthnContext'));

        self::expectException(NoAuthnContextSamlResponseException::class);
        $this->postBinding->processResponse($request, $idp, $sp);
    }
    public function test_process_response_authn_failed()
    {
        $request = $this->buildRequest();

        $request->setMethod(Request::METHOD_POST);
        $idp = m::mock(IdentityProvider::class);
        $sp = m::mock(ServiceProvider::class);
        $sp
            ->shouldReceive('getAssertionConsumerUrl')
            ->andReturn('https://stepup.example.com/acs');
        $assertions = m::mock(ArrayCollection::class);
        $assertions->shouldReceive('getOnlyElement')->andReturn(m::mock(Assertion::class));
        $this->processor->shouldReceive('process')->andThrow(new PreconditionNotMetException('urn:oasis:names:tc:SAML:2.0:status:AuthnFailed'));

        self::expectException(AuthnFailedSamlResponseException::class);
        $this->postBinding->processResponse($request, $idp, $sp);
    }
    public function test_process_response_other_precondition_not_met()
    {
        $request = $this->buildRequest();

        $request->setMethod(Request::METHOD_POST);
        $idp = m::mock(IdentityProvider::class);
        $sp = m::mock(ServiceProvider::class);
        $sp
            ->shouldReceive('getAssertionConsumerUrl')
            ->andReturn('https://stepup.example.com/acs');
        $assertions = m::mock(ArrayCollection::class);
        $assertions->shouldReceive('getOnlyElement')->andReturn(m::mock(Assertion::class));
        $this->processor->shouldReceive('process')->andThrow(new PreconditionNotMetException('Arbitrary'));

        self::expectException(PreconditionNotMetException::class);
        $this->postBinding->processResponse($request, $idp, $sp);
    }
}
