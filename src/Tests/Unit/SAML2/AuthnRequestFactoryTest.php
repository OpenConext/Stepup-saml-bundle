<?php declare(strict_types=1);

/**
 * Copyright 2015 SURFnet B.V.
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

use Mockery as m;
use Mockery\Adapter\Phpunit\MockeryPHPUnitIntegration;
use PHPUnit\Framework\TestCase;
use SAML2\Configuration\PrivateKey;
use Surfnet\SamlBundle\Entity\IdentityProvider;
use Surfnet\SamlBundle\Entity\ServiceProvider;
use Surfnet\SamlBundle\Http\Exception\InvalidRequestException;
use Surfnet\SamlBundle\SAML2\AuthnRequest;
use Surfnet\SamlBundle\SAML2\AuthnRequestFactory;
use Symfony\Component\HttpFoundation\Request;

class AuthnRequestFactoryTest extends TestCase
{
    use MockeryPHPUnitIntegration;

    /**
     * @test
     * @group saml2
     */
    public function an_exception_is_thrown_when_a_request_is_not_properly_base64_encoded(): void
    {
        $this->expectExceptionMessage("Failed decoding the request, did not receive a valid base64 string");
        $this->expectException(InvalidRequestException::class);
        $invalidCharacter = '$';
        $queryParams      = [AuthnRequest::PARAMETER_REQUEST => $invalidCharacter];
        $serverParams     = [
            'REQUEST_URI' => sprintf('https://test.example?%s=%s', AuthnRequest::PARAMETER_REQUEST, $invalidCharacter),
        ];
        $request          = new Request($queryParams, [], [], [], [], $serverParams);

        AuthnRequestFactory::createFromHttpRequest($request);
    }

    /**
     * @test
     * @group saml2
     */
    public function an_exception_is_thrown_when_a_request_cannot_be_inflated(): void
    {
        $this->expectExceptionMessage("Failed inflating the request;");
        $this->expectException(InvalidRequestException::class);
        $nonDeflated  = base64_encode('nope, not deflated');
        $queryParams  = [AuthnRequest::PARAMETER_REQUEST => $nonDeflated];
        $serverParams = [
            'REQUEST_URI' => sprintf('https://test.example?%s=%s', AuthnRequest::PARAMETER_REQUEST, $nonDeflated),
        ];
        $request = new Request($queryParams, [], [], [], [], $serverParams);

        AuthnRequestFactory::createFromHttpRequest($request);
    }

    /**
     * @test
     * @group saml2
     */
    public function verify_force_authn_works_as_intended(): void
    {
        $sp = m::mock(ServiceProvider::class);
        $sp->shouldReceive('getAssertionConsumerUrl')->andReturn('https://example-sp.com/acs');
        $sp->shouldReceive('getEntityId')->andReturn('https://example-sp.com/');

        $pk = new PrivateKey(__DIR__.'/../../../Resources/keys/development_privatekey.pem', 'key-for-test', '');

        $sp->shouldReceive('getPrivateKey')->andReturn($pk);

        $idp = m::mock(IdentityProvider::class);
        $idp->shouldReceive('getSsoUrl')->andReturn('https://example-idp.com/sso');

        $authnRequest = AuthnRequestFactory::createNewRequest($sp, $idp, true);
        $this->assertTrue($authnRequest->isForceAuthn());
        $authnRequest = AuthnRequestFactory::createNewRequest($sp, $idp, false);
        $this->assertFalse($authnRequest->isForceAuthn());
    }
}
