<?php

namespace Surfnet\SamlBundle\Tests\SAML2;

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
        // the $ is invalid since it is outside the base64 alphabet and we deserialize in strict mode.
        $request = new Request([AuthnRequest::PARAMETER_REQUEST => '$']);

        AuthnRequestFactory::createFromHttpRequest($request);
    }

    /**
     * @test
     * @group                    saml2
     *
     * @expectedException \Surfnet\SamlBundle\Http\Exception\InvalidRequestException
     * @expectedExceptionMessage Failed inflating the request;
     */
    public function an_exception_is_thrown_when_a_request_cannot_be_inflated()
    {
        // the $ is invalid since it is outside the base64 alphabet and we deserialize in strict mode.
        $request = new Request([AuthnRequest::PARAMETER_REQUEST => base64_encode('nope, not deflated')]);

        AuthnRequestFactory::createFromHttpRequest($request);
    }
}
