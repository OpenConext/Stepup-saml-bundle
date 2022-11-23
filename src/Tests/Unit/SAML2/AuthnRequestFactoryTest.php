<?php

namespace Surfnet\SamlBundle\Tests\Unit\SAML2;

use Mockery as m;
use Mockery\Adapter\Phpunit\MockeryTestCase;
use PHPUnit\Framework\TestCase as UnitTest;
use RobRichards\XMLSecLibs\XMLSecurityKey;
use SAML2\Configuration\PrivateKey;
use Surfnet\SamlBundle\Entity\IdentityProvider;
use Surfnet\SamlBundle\Entity\ServiceProvider;
use Surfnet\SamlBundle\SAML2\AuthnRequest;
use Surfnet\SamlBundle\SAML2\AuthnRequestFactory;
use Symfony\Component\HttpFoundation\Request;

class AuthnRequestFactoryTest extends MockeryTestCase
{
    /**
     * @test
     * @group saml2
     *
     * @expectedException \Surfnet\SamlBundle\Http\Exception\InvalidRequestException
     * @expectedExceptionMessage Failed decoding the request, did not receive a valid base64 string
     */
    public function an_exception_is_thrown_when_a_request_is_not_properly_base64_encoded()
    {
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
     *
     * @expectedException \Surfnet\SamlBundle\Http\Exception\InvalidRequestException
     * @expectedExceptionMessage Failed inflating the request;
     */
    public function an_exception_is_thrown_when_a_request_cannot_be_inflated()
    {
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
    public function verify_force_authn_works_as_intended()
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
