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

use LogicException;
use Mockery as m;
use Mockery\Adapter\Phpunit\MockeryPHPUnitIntegration;
use PHPUnit\Framework\TestCase;
use SAML2\Compat\ContainerSingleton;
use SAML2\Compat\MockContainer;
use SAML2\Response\Processor;
use Surfnet\SamlBundle\Entity\ServiceProvider;
use Surfnet\SamlBundle\Entity\ServiceProviderRepository;
use Surfnet\SamlBundle\Http\Exception\SignatureValidationFailedException;
use Surfnet\SamlBundle\Http\Exception\UnknownServiceProviderException;
use Surfnet\SamlBundle\Http\PostBinding;
use Surfnet\SamlBundle\SAML2\ReceivedAuthnRequest;
use Surfnet\SamlBundle\Signing\SignatureVerifier;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpKernel\Exception\BadRequestHttpException;

class PostBindingAuthnRequestTest extends TestCase
{
    use MockeryPHPUnitIntegration;

    private const RAW_MESSAGE = <<<MESSAGE
<?xml version="1.0"?>
<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" Destination="%s" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="aaf23196-1773-2113-474a-fe114412ab72" Version="2.0" IssueInstant="2004-12-05T09:21:59Z" AssertionConsumerServiceIndex="0" AttributeConsumingServiceIndex="0"><saml:Issuer>https://sp.example.com/SAML2</saml:Issuer><samlp:NameIDPolicy Format="urn:oasis:names:tc:SAML:2.0:nameid-format:transient" AllowCreate="true"/></samlp:AuthnRequest>

MESSAGE;
    private const RAW_MESSAGE_NO_DESTINATION = <<<MESSAGE
<?xml version="1.0"?>
<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="aaf23196-1773-2113-474a-fe114412ab72" Version="2.0" IssueInstant="2004-12-05T09:21:59Z" AssertionConsumerServiceIndex="0" AttributeConsumingServiceIndex="0"><saml:Issuer>https://sp.example.com/SAML2</saml:Issuer><samlp:NameIDPolicy Format="urn:oasis:names:tc:SAML:2.0:nameid-format:transient" AllowCreate="true"/></samlp:AuthnRequest>

MESSAGE;

    private PostBinding $postBinding;

    private m\MockInterface&ServiceProviderRepository $entityRepository;

    private m\MockInterface&SignatureVerifier $signatureVerifier;

    public function setUp(): void
    {
        $this->entityRepository = m::mock(ServiceProviderRepository::class);
        $this->signatureVerifier = m::mock(SignatureVerifier::class);
        $this->postBinding = new PostBinding(
            m::mock(Processor::class),
            $this->signatureVerifier,
            $this->entityRepository
        );
        ContainerSingleton::setContainer(new MockContainer());
    }

    public function test_receive_signed_authn_request_happy_flow(): void
    {
        $requestUri = 'https://stepup.example.com/sso?with-some-addition=true';
        $post = [
            'SAMLRequest' => base64_encode(sprintf(self::RAW_MESSAGE, 'https://stepup.example.com/sso')),
            'RelayState' => '',
        ];
        $request = new Request([], $post, [], [], [], ['REQUEST_URI' => $requestUri]);
        $request->setMethod(Request::METHOD_POST);

        $this->entityRepository
            ->shouldReceive('hasServiceProvider')
            ->once()
            ->andReturn(true);

        $sp = m::mock(ServiceProvider::class);
        $this->entityRepository
            ->shouldReceive('getServiceProvider')
            ->once()
            ->andReturn($sp);

        $this->signatureVerifier
            ->shouldReceive('verifyIsSignedBy')
            ->once()
            ->andReturn(true);

        $authnRequest = $this->postBinding->receiveSignedAuthnRequestFrom($request);

        self::assertInstanceOf(ReceivedAuthnRequest::class, $authnRequest);
        self::assertEquals('https://stepup.example.com/sso', $authnRequest->getDestination());
    }

    public function test_receive_signed_authn_request_must_have_sp_repo(): void
    {
        $requestUri = 'https://stepup.example.com/sso?with-some-addition=true';
        $post = [
            'SAMLRequest' => base64_encode(sprintf(self::RAW_MESSAGE, 'https://stepup.example.com/sso')),
            'RelayState' => '',
        ];
        $request = new Request([], $post, [], [], [], ['REQUEST_URI' => $requestUri]);
        self::expectException(LogicException::class);
        self::expectExceptionMessage('Could not receive AuthnRequest from HTTP Request: a ServiceProviderRepository must be configured');
        $postBinding = new PostBinding(
            m::mock(Processor::class),
            $this->signatureVerifier,
            null
        );
        $postBinding->receiveSignedAuthnRequestFrom($request);
    }

    public function test_receive_signed_authn_request_http_request_must_be_post(): void
    {
        $requestUri = 'https://stepup.example.com/sso?with-some-addition=true';
        $post = [
            'SAMLRequest' => base64_encode(sprintf(self::RAW_MESSAGE, 'https://stepup.example.com/sso')),
            'RelayState' => '',
        ];
        $request = new Request([], $post, [], [], [], ['REQUEST_URI' => $requestUri]);
        self::expectException(BadRequestHttpException::class);
        self::expectExceptionMessage('Could not receive AuthnRequest from HTTP Request: expected a POST method, got GET');

        $this->postBinding->receiveSignedAuthnRequestFrom($request);
    }

    public function test_receive_signed_authn_request_must_have_destination(): void
    {
        $requestUri = 'https://stepup.example.com/sso?with-some-addition=true';
        $post = [
            'SAMLRequest' => base64_encode(self::RAW_MESSAGE_NO_DESTINATION),
            'RelayState' => '',
        ];
        $request = new Request([], $post, [], [], [], ['REQUEST_URI' => $requestUri]);
        $request->setMethod(Request::METHOD_POST);
        self::expectException(BadRequestHttpException::class);
        self::expectExceptionMessage('A signed AuthnRequest must have the Destination attribute');

        $this->postBinding->receiveSignedAuthnRequestFrom($request);
    }

    public function test_receive_signed_authn_request_request_uri_must_start_with_destination(): void
    {
        $requestUri = 'https://stepup.example.com/sso';
        $post = [
            'SAMLRequest' => base64_encode(sprintf(self::RAW_MESSAGE, 'https://openconext.example.com/sso')),
            'RelayState' => '',
        ];
        $request = new Request([], $post, [], [], [], ['REQUEST_URI' => $requestUri]);
        $request->setMethod(Request::METHOD_POST);

        self::expectException(BadRequestHttpException::class);
        self::expectExceptionMessage('Actual Destination "https://stepup.example.com/sso" does not match the AuthnRequest Destination "https://openconext.example.com/sso"');

        $this->postBinding->receiveSignedAuthnRequestFrom($request);
    }

    public function test_receive_signed_authn_request_unknown_sp(): void
    {
        $requestUri = 'https://stepup.example.com/sso';
        $post = [
            'SAMLRequest' => base64_encode(sprintf(self::RAW_MESSAGE, 'https://stepup.example.com/sso')),
            'RelayState' => '',
        ];
        $request = new Request([], $post, [], [], [], ['REQUEST_URI' => $requestUri]);
        $request->setMethod(Request::METHOD_POST);

        $this->entityRepository
            ->shouldReceive('hasServiceProvider')
            ->once()
            ->andReturn(false);

        self::expectException(UnknownServiceProviderException::class);
        self::expectExceptionMessage('AuthnRequest received from ServiceProvider with an unknown EntityId: "https://sp.example.com/SAML2"');

        $this->postBinding->receiveSignedAuthnRequestFrom($request);
    }

    public function test_receive_signed_authn_request_signature_validation_failed(): void
    {
        $requestUri = 'https://stepup.example.com/sso';
        $post = [
            'SAMLRequest' => base64_encode(sprintf(self::RAW_MESSAGE, 'https://stepup.example.com/sso')),
            'RelayState' => '',
        ];
        $request = new Request([], $post, [], [], [], ['REQUEST_URI' => $requestUri]);
        $request->setMethod(Request::METHOD_POST);

        $this->entityRepository
            ->shouldReceive('hasServiceProvider')
            ->once()
            ->andReturn(true);

        $sp = m::mock(ServiceProvider::class);
        $this->entityRepository
            ->shouldReceive('getServiceProvider')
            ->once()
            ->andReturn($sp);

        $this->signatureVerifier
            ->shouldReceive('verifyIsSignedBy')
            ->once()
            ->andReturn(false);

        self::expectException(SignatureValidationFailedException::class);
        self::expectExceptionMessage('Validation of the signature in the AuthnRequest failed');

        $this->postBinding->receiveSignedAuthnRequestFrom($request);
    }
}
