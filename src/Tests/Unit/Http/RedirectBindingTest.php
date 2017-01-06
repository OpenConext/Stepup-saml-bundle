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
use Surfnet\SamlBundle\Http\RedirectBinding;
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
     * @expectedExceptionMessage There should be exactly one "SAMLRequest" parameter
     * @expectedExceptionMessage There were 0
     */
    public function an_exception_is_thrown_when_an_unsigned_request_has_no_saml_request_parameter()
    {
        $requestUri = 'https://sso.my-service.example?Signature=some-signature';

        $request = new Request;
        $request->server->set('REQUEST_URI', $requestUri);

        $this->redirectBinding->processUnsignedRequest($request);
    }

    /**
     * @test
     * @group http
     *
     * @expectedException \Symfony\Component\HttpKernel\Exception\BadRequestHttpException
     * @expectedExceptionMessage There should be exactly one "SAMLRequest" parameter
     * @expectedExceptionMessage there were 2
     */
    public function an_exception_is_thrown_when_an_unsigned_request_has_more_than_one_saml_request_parameter()
    {
        $requestUri = 'https://sso.my-service.example?'
            . 'SAMLRequest=some-saml-request'
            . '&Signature=some-signature'
            . '&SigAlg=sig-alg'
            . '&SAMLRequest=another-saml-request';

        $request = new Request;
        $request->server->set('REQUEST_URI', $requestUri);

        $this->redirectBinding->processUnsignedRequest($request);
    }

    /**
     * @test
     * @group http
     * @expectedException \Symfony\Component\HttpKernel\Exception\BadRequestHttpException
     * @expectedExceptionMessage There should be no or one "RelayState" parameter
     * @expectedExceptionMessage there were 2
     */
    public function an_exception_is_thrown_when_an_unsigned_request_has_more_than_one_relay_state()
    {
        $requestUri = 'https://sso.my-service.example?'
            . 'SAMLRequest=some-saml-request'
            . '&Signature=some-signature'
            . '&SigAlg=some-sig-alg'
            . '&RelayState=some-relay-state'
            . '&RelayState=another-relay-state';

        $request = new Request;
        $request->server->set('REQUEST_URI', $requestUri);

        $this->redirectBinding->processUnsignedRequest($request);
    }

    /**
     * @test
     * @group http
     *
     * @expectedException \Symfony\Component\HttpKernel\Exception\BadRequestHttpException
     * @expectedExceptionMessage There should be exactly one "SAMLRequest" parameter
     * @expectedExceptionMessage There were 0
     */
    public function an_exception_is_thrown_when_a_signed_request_has_no_saml_request_parameter()
    {
        $requestUri = 'https://sso.my-service.example?Signature=some-signature';

        $request = new Request;
        $request->server->set('REQUEST_URI', $requestUri);

        $this->redirectBinding->processSignedRequest($request);
    }

    /**
     * @test
     * @group http
     *
     * @expectedException \Symfony\Component\HttpKernel\Exception\BadRequestHttpException
     * @expectedExceptionMessage There should be exactly one "SAMLRequest" parameter
     * @expectedExceptionMessage there were 2
     */
    public function an_exception_is_thrown_when_a_signed_request_has_more_than_one_saml_request_parameter()
    {
        $requestUri = 'https://sso.my-service.example?'
            . 'SAMLRequest=some-saml-request'
            . '&Signature=some-signature'
            . '&SigAlg=sig-alg'
            . '&SAMLRequest=another-saml-request';

        $request = new Request;
        $request->server->set('REQUEST_URI', $requestUri);

        $this->redirectBinding->processSignedRequest($request);
    }

    /**
     * @test
     * @group http
     *
     * @expectedException \Symfony\Component\HttpKernel\Exception\BadRequestHttpException
     * @expectedExceptionMessage There should be exactly one "Signature" parameter
     * @expectedExceptionMessage There were 0
     */
    public function an_exception_is_thrown_when_a_signed_request_has_no_signature()
    {
        $requestUri = 'https://sso.my-service.example?SAMLRequest=some-saml-request';

        $request = new Request;
        $request->server->set('REQUEST_URI', $requestUri);

        $this->redirectBinding->processSignedRequest($request);
    }

    /**
     * @test
     * @group http
     *
     * @expectedException \Symfony\Component\HttpKernel\Exception\BadRequestHttpException
     * @expectedExceptionMessage There should be exactly one "SigAlg" parameter
     * @expectedExceptionMessage there were 0
     */
    public function an_exception_is_thrown_when_a_signed_request_has_no_signature_algorithm(
    )
    {
        $requestUri = 'https://sso.my-service.example?SAMLRequest=some-saml-request&Signature=some-signature';

        $request = new Request;
        $request->server->set('REQUEST_URI', $requestUri);

        $this->redirectBinding->processSignedRequest($request);
    }

    /**
     * @test
     * @group http
     * @expectedException \Symfony\Component\HttpKernel\Exception\BadRequestHttpException
     * @expectedExceptionMessage There should be no or one "RelayState" parameter
     * @expectedExceptionMessage there were 2
     */
    public function an_exception_is_thrown_when_a_signed_request_has_more_than_one_relay_state()
    {
        $requestUri = 'https://sso.my-service.example?'
            . 'SAMLRequest=some-saml-request'
            . '&Signature=some-signature'
            . '&SigAlg=some-sig-alg'
            . '&RelayState=some-relay-state'
            . '&RelayState=another-relay-state';

        $request = new Request;
        $request->server->set('REQUEST_URI', $requestUri);

        $this->redirectBinding->processSignedRequest($request);
    }
}
