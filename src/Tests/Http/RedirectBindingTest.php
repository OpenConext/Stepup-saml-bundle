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
use Surfnet\SamlBundle\Http\RedirectBinding;
use Surfnet\SamlBundle\SAML2\AuthnRequest;
use Surfnet\SamlBundle\SAML2\BridgeContainer;

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
            $this->entityRepository,
            m::mock('Psr\Log\LoggerInterface'),
            m::mock('Surfnet\SamlBundle\Signing\SignatureVerifier')
        );
    }

    /**
     * @group http
     * @test
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
     * @group http
     * @test
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
}
