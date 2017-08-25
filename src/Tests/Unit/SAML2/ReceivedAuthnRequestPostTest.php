<?php

/**
 * Copyright 2017 SURFnet B.V.
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

namespace Tests\Unit\SAML2;

use PHPUnit_Framework_TestCase as TestCase;
use Surfnet\SamlBundle\Http\ReceivedAuthnRequestPost;

class ReceivedAuthnRequestPostTest extends TestCase
{
    /**
     * @test
     */
    public function it_can_decode_a_signed_saml_request()
    {
        $samlRequest = str_replace(PHP_EOL, '', file_get_contents(__DIR__ . '/Resources/valid-signed.xml'));
        $parameters = [
            'SAMLRequest' => base64_encode($samlRequest),
            'RelayState' => '/index.php',
        ];
        $authnRequest = ReceivedAuthnRequestPost::parse($parameters);
        $this->assertEquals('/index.php', $authnRequest->getRelayState());
    }

    /**
     * @test
     */
    public function it_can_decode_a_signed_saml_request_from_adfs_origin()
    {
        $samlRequest = str_replace(PHP_EOL, '', file_get_contents(__DIR__ . '/Resources/valid-signed-adfs.xml'));
        $parameters = [
            'SAMLRequest' => base64_encode($samlRequest),
            'RelayState' => '/index.php',
        ];
        $authnRequest = ReceivedAuthnRequestPost::parse($parameters);
    }

    /**
     * @test
     */
    public function it_can_decode_an_usigned_saml_request()
    {
        $samlRequest = str_replace(PHP_EOL, '', file_get_contents(__DIR__ . '/Resources/valid-unsigned.xml'));
        $parameters = [
            'SAMLRequest' => base64_encode($samlRequest),
            'RelayState' => '/index.php',
        ];
        $authnRequest = ReceivedAuthnRequestPost::parse($parameters);
        $this->assertEquals('/index.php', $authnRequest->getRelayState());
    }

//    /**
//     * @test
//     * @expectedException \Surfnet\SamlBundle\Http\Exception\InvalidRequestException
//     * @expectedExceptionMessage Failed decoding SAML request, did not receive a valid base64 string
//     */
//    public function it_rejects_malformed_saml_request()
//    {
//        $parameters = [
//            'SAMLRequest' => 'this=notvalid==',
//            'RelayState' => '/index.php',
//        ];
//        ReceivedAuthnRequestPost::parse($parameters);
//    }
//
//    /**
//     * @test
//     * @expectedException \Surfnet\SamlBundle\Http\Exception\InvalidReceivedAuthnRequestPostException
//     * @expectedExceptionMessage Invalid ReceivedAuthnRequest: AuthnRequest contains a signature algorithm but not a signature
//     */
//    public function it_rejects_request_with_missing_signature()
//    {
//        $samlRequest = str_replace(PHP_EOL, '', file_get_contents(__DIR__ . '/Resources/invalid-missing-signature-value.xml'));
//        $parameters = [
//            'SAMLRequest' => base64_encode($samlRequest),
//            'RelayState' => '/index.php',
//        ];
//        ReceivedAuthnRequestPost::parse($parameters);
//    }
//
//    /**
//     * @test
//     * @expectedException \Surfnet\SamlBundle\Http\Exception\InvalidReceivedAuthnRequestPostException
//     * @expectedExceptionMessage Invalid ReceivedAuthnRequest:: signature is not base64 encoded correctly
//     */
//    public function it_rejects_request_with_malformed_signature()
//    {
//        $samlRequest = str_replace(PHP_EOL, '', file_get_contents(__DIR__ . '/Resources/invalid-malformed-signature-value.xml'));
//        $parameters = [
//            'SAMLRequest' => base64_encode($samlRequest),
//            'RelayState' => '/index.php',
//        ];
//        ReceivedAuthnRequestPost::parse($parameters);
//    }
//
//    /**
//     * @test
//     * @expectedException \Surfnet\SamlBundle\Http\Exception\InvalidReceivedAuthnRequestPostException
//     * @expectedExceptionMessage Invalid ReceivedAuthnRequest: AuthnRequest contains a signature algorithm but not a signature
//     */
//    public function it_rejects_request_with_empty_signature()
//    {
//        $samlRequest = str_replace(PHP_EOL, '', file_get_contents(__DIR__ . '/Resources/invalid-empty-signature-value.xml'));
//        $parameters = [
//            'SAMLRequest' => base64_encode($samlRequest),
//            'RelayState' => '/index.php',
//        ];
//        ReceivedAuthnRequestPost::parse($parameters);
//    }
//
//    /**
//     * @test
//     * @expectedException \Surfnet\SamlBundle\Http\Exception\InvalidReceivedAuthnRequestPostException
//     * @expectedExceptionMessage Invalid ReceivedAuthnRequest: AuthnRequest contains a signature but not a signature algorithm
//     */
//    public function it_rejects_request_with_missing_signing_algorithm()
//    {
//        $samlRequest = str_replace(PHP_EOL, '', file_get_contents(__DIR__ . '/Resources/invalid-missing-signing-algorithm.xml'));
//        $parameters = [
//            'SAMLRequest' => base64_encode($samlRequest),
//            'RelayState' => '/index.php',
//        ];
//        ReceivedAuthnRequestPost::parse($parameters);
//    }
//
//    /**
//     * @test
//     * @expectedException \Surfnet\SamlBundle\Exception\RuntimeException
//     * @expectedExceptionMessage Cannot decode signature: SAMLRequest is not signed
//     */
//    public function it_can_not_get_a_decoded_signature_of_an_unsigned_request()
//    {
//        $samlRequest = str_replace(PHP_EOL, '', file_get_contents(__DIR__ . '/Resources/valid-unsigned.xml'));
//        $parameters = [
//            'SAMLRequest' => base64_encode($samlRequest),
//            'RelayState' => '/index.php',
//        ];
//        $authnRequest = ReceivedAuthnRequestPost::parse($parameters);
//        $authnRequest->getDecodedSignature();
//    }

}
