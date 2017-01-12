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

namespace Surfnet\SamlBundle\Tests\Http;

use Mockery as m;
use PHPUnit_Framework_TestCase as UnitTest;
use Psr\Log\NullLogger;
use Surfnet\SamlBundle\Entity\ServiceProvider;
use Surfnet\SamlBundle\Http\ReceivedAuthnRequestQueryString;
use Surfnet\SamlBundle\Http\RedirectBinding;
use Surfnet\SamlBundle\SAML2\AuthnRequest;
use Symfony\Component\HttpFoundation\Request;

class RedirectBindingTest extends UnitTest
{
    const ENCODED_MESSAGE = 'fZFfa8IwFMXfBb9DyXvaJtZ1BqsURRC2Mabbw95ivc5Am3TJrXPffmmLY3%2FA15Pzuyf33On8XJXBCaxTRmeEhTEJQBdmr%2FRbRp63K3pL5rPhYOpkVdYib%2FCon%2BC9AYfDQRB4WDvRvWWksVoY6ZQTWlbgBBZik9%2FfCR7GorYGTWFK8pu6DknnwKL%2FWEetlxmR8sBHbHJDWZqOKGdsRJM0kfQAjCUJ43KX8s78ctnIz%2Blp5xpYa4dSo1fjOKGM03i8jSeCMzGevHa2%2FBK5MNo1FdgN2JMqPLmHc0b6WTmiVbsGoTf5qv66Zq2t60x0wXZ2RKydiCJXh3CWVV1CWJgqanfl0%2Bin8xutxYOvZL18NKUqPlvZR5el%2BVhYkAgZQdsA6fWVsZXE63W2itrTQ2cVaKV2CjSSqL1v9P%2FAXv4C';
    const RAW_MESSAGE = <<<MESSAGE
<?xml version="1.0"?>
<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="aaf23196-1773-2113-474a-fe114412ab72" Version="2.0" IssueInstant="2004-12-05T09:21:59Z" AssertionConsumerServiceIndex="0" AttributeConsumingServiceIndex="0"><saml:Issuer>https://sp.example.com/SAML2</saml:Issuer><samlp:NameIDPolicy Format="urn:oasis:names:tc:SAML:2.0:nameid-format:transient" AllowCreate="true"/></samlp:AuthnRequest>

MESSAGE;

    /**
     * @var \Surfnet\SamlBundle\Http\RedirectBinding
     */
    private $redirectBinding;

    /**
     * @var \Mockery\MockInterface
     */
    private $entityRepository;

    public function setUp()
    {
        $this->entityRepository = m::mock('Surfnet\SamlBundle\Entity\ServiceProviderRepository');
        $this->redirectBinding = new RedirectBinding(
            m::mock('Psr\Log\LoggerInterface'),
            m::mock('Surfnet\SamlBundle\Signing\SignatureVerifier'),
            $this->entityRepository
        );
    }

    /**
     * @test
     * @group http
     *
     * @expectedException \Symfony\Component\HttpKernel\Exception\BadRequestHttpException
     */
    public function an_exception_is_thrown_when_the_request_get_parameter_is_not_set()
    {
        $request = m::mock('Symfony\Component\HttpFoundation\Request')
            ->shouldReceive('get')
                ->with(AuthnRequest::PARAMETER_REQUEST)
                ->andReturnNull()
        ->getMock();

        $this->redirectBinding->processRequest($request);
    }

    /**
     * @test
     * @group http
     *
     * @expectedException \Symfony\Component\HttpKernel\Exception\BadRequestHttpException
     */
    public function an_exception_is_thrown_when_the_request_is_signed_but_has_no_sigalg_parameter()
    {
        $request = m::mock('Symfony\Component\HttpFoundation\Request');
        $request->shouldReceive('get')
            ->with(AuthnRequest::PARAMETER_REQUEST)
            ->andReturn('foo');

        $request->shouldReceive('get')
            ->with(AuthnRequest::PARAMETER_SIGNATURE)
            ->andReturn('somesignature');

        $request->shouldReceive('get')
            ->with(AuthnRequest::PARAMETER_SIGNATURE_ALGORITHM)
            ->andReturn();

        $this->redirectBinding->processRequest($request);
    }

    /**
     * @test
     * @group http
     *
     * @dataProvider nonGetMethodProvider
     */
    public function a_signed_authn_request_cannot_be_received_from_a_request_that_is_not_a_get_request($nonGetMethod)
    {
        $this->setExpectedException(
            '\Symfony\Component\HttpKernel\Exception\BadRequestHttpException',
            sprintf('expected a GET method, got %s', $nonGetMethod)
        );

        $dummySignatureVerifier = m::mock('\Surfnet\SamlBundle\Signing\SignatureVerifier');
        $dummyEntityRepository  = m::mock('\Surfnet\SamlBundle\Entity\ServiceProviderRepository');
        $redirectBinding = new RedirectBinding(new NullLogger(), $dummySignatureVerifier, $dummyEntityRepository);

        $request = new Request();
        $request->setMethod($nonGetMethod);

        $redirectBinding->receiveSignedAuthnRequestFrom($request);
    }

    /**
     * @test
     * @group http
     */
    public function a_signed_authn_request_cannot_be_received_from_a_request_that_has_no_signed_saml_request()
    {
        $this->setExpectedException(
            '\Symfony\Component\HttpKernel\Exception\BadRequestHttpException',
            'The SAMLRequest is expected to be signed but it was not'
        );

        $dummySignatureVerifier = m::mock('\Surfnet\SamlBundle\Signing\SignatureVerifier');
        $dummyEntityRepository  = m::mock('\Surfnet\SamlBundle\Entity\ServiceProviderRepository');

        $requestUri = 'https://my-service-provider.example?'
            . ReceivedAuthnRequestQueryString::PARAMETER_REQUEST . '=' . self::ENCODED_MESSAGE;
        $request = new Request([], [], [], [], [], ['REQUEST_URI' => $requestUri]);

        $redirectBinding = new RedirectBinding(new NullLogger(), $dummySignatureVerifier, $dummyEntityRepository);
        $redirectBinding->receiveSignedAuthnRequestFrom($request);
    }

    /**
     * @test
     * @group http
     */
    public function a_signed_authn_request_cannot_be_received_if_the_service_provider_in_the_authn_request_is_unknown()
    {
        $this->setExpectedException(
            '\Surfnet\SamlBundle\Http\Exception\UnknownServiceProviderException',
            'AuthnRequest received from ServiceProvider with an unknown EntityId'
        );

        $dummySignatureVerifier = m::mock('\Surfnet\SamlBundle\Signing\SignatureVerifier');
        $mockEntityRepository   = m::mock('\Surfnet\SamlBundle\Entity\ServiceProviderRepository');

        $requestUri = 'https://my-service-provider.example?'
            . ReceivedAuthnRequestQueryString::PARAMETER_REQUEST . '=' . self::ENCODED_MESSAGE
            . '&' . ReceivedAuthnRequestQueryString::PARAMETER_SIGNATURE . '=signature'
            . '&' . ReceivedAuthnRequestQueryString::PARAMETER_SIGNATURE_ALGORITHM . '=signature-algorithm';

        $request = new Request([], [], [], [], [], ['REQUEST_URI' => $requestUri]);

        $mockEntityRepository
            ->shouldReceive('hasServiceProvider')
            ->once()
            ->andReturn(false);

        $redirectBinding = new RedirectBinding(new NullLogger(), $dummySignatureVerifier, $mockEntityRepository);
        $redirectBinding->receiveSignedAuthnRequestFrom($request);
    }
    /**
     * @test
     * @group http
     */
    public function a_signed_authn_request_cannot_be_received_if_the_signature_is_invalid()
    {
        $this->setExpectedException(
            '\Symfony\Component\HttpKernel\Exception\BadRequestHttpException',
            'signature could not be validated'
        );

        $mockSignatureVerifier = m::mock('\Surfnet\SamlBundle\Signing\SignatureVerifier');
        $mockEntityRepository  = m::mock('\Surfnet\SamlBundle\Entity\ServiceProviderRepository');

        $requestUri = 'https://my-service-provider.example?'
            . ReceivedAuthnRequestQueryString::PARAMETER_REQUEST . '=' . self::ENCODED_MESSAGE
            . '&' . ReceivedAuthnRequestQueryString::PARAMETER_SIGNATURE . '=signature'
            . '&' . ReceivedAuthnRequestQueryString::PARAMETER_SIGNATURE_ALGORITHM . '=signature-algorithm';
        ;
        $request = new Request([], [], [], [], [], ['REQUEST_URI' => $requestUri]);

        $mockEntityRepository
            ->shouldReceive('hasServiceProvider')
            ->once()
            ->andReturn(true);
        $mockEntityRepository
            ->shouldReceive('getServiceProvider')
            ->once()
            ->andReturn(new ServiceProvider([]));

        $mockSignatureVerifier
            ->shouldReceive('verify')
            ->once()
            ->andReturn(false);

        $redirectBinding = new RedirectBinding(new NullLogger(), $mockSignatureVerifier, $mockEntityRepository);
        $redirectBinding->receiveSignedAuthnRequestFrom($request);
    }
    /**
     * @test
     * @group http
     *
     * @dataProvider nonGetMethodProvider
     */
    public function a_unsigned_authn_request_cannot_be_received_from_a_request_that_is_not_a_get_request($nonGetMethod)
    {
        $this->setExpectedException(
            '\Symfony\Component\HttpKernel\Exception\BadRequestHttpException',
            sprintf('expected a GET method, got %s', $nonGetMethod)
        );

        $dummySignatureVerifier = m::mock('\Surfnet\SamlBundle\Signing\SignatureVerifier');
        $dummyEntityRepository  = m::mock('\Surfnet\SamlBundle\Entity\ServiceProviderRepository');
        $redirectBinding = new RedirectBinding(new NullLogger(), $dummySignatureVerifier, $dummyEntityRepository);

        $request = new Request();
        $request->setMethod($nonGetMethod);

        $redirectBinding->receiveUnsignedAuthnRequestFrom($request);
    }

    /**
     * @test
     * @group http
     */
    public function a_unsigned_authn_request_cannot_be_received_if_the_service_provider_in_the_authn_request_is_unknown()
    {
        $this->setExpectedException(
            '\Surfnet\SamlBundle\Http\Exception\UnknownServiceProviderException',
            'AuthnRequest received from ServiceProvider with an unknown EntityId'
        );

        $dummySignatureVerifier = m::mock('\Surfnet\SamlBundle\Signing\SignatureVerifier');
        $dummyEntityRepository  = m::mock('\Surfnet\SamlBundle\Entity\ServiceProviderRepository');

        $requestUri = 'https://my-service-provider.example?'
            . ReceivedAuthnRequestQueryString::PARAMETER_REQUEST . '=' . self::ENCODED_MESSAGE
            . '&' . ReceivedAuthnRequestQueryString::PARAMETER_SIGNATURE . '=signature'
            . '&' . ReceivedAuthnRequestQueryString::PARAMETER_SIGNATURE_ALGORITHM . '=signature-algorithm';
        ;
        $request = new Request([], [], [], [], [], ['REQUEST_URI' => $requestUri]);

        $dummyEntityRepository
            ->shouldReceive('hasServiceProvider')
            ->once()
            ->andReturn(false);

        $redirectBinding = new RedirectBinding(new NullLogger(), $dummySignatureVerifier, $dummyEntityRepository);
        $redirectBinding->receiveUnsignedAuthnRequestFrom($request);
    }

    public function nonGetMethodProvider()
    {
        return [
            [Request::METHOD_POST],
            [Request::METHOD_PATCH],
            [Request::METHOD_HEAD],
            [Request::METHOD_PUT],
            [Request::METHOD_PURGE],
            [Request::METHOD_CONNECT],
            [Request::METHOD_OPTIONS],
            [Request::METHOD_TRACE],
        ];
    }
}
