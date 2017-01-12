<?php

namespace Surfnet\SamlBundle\Tests\Unit\SAML2;

use PHPUnit_Framework_TestCase as UnitTest;
use Surfnet\SamlBundle\SAML2\AuthnRequest;
use Surfnet\SamlBundle\SAML2\AuthnRequestFactory;
use Symfony\Component\HttpFoundation\Request;

class AuthnRequestFactoryTest extends UnitTest
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
}
