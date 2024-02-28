<?php declare(strict_types=1);

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

use PHPUnit\Framework\TestCase;
use Surfnet\SamlBundle\Http\Exception\InvalidRequestException;
use Surfnet\SamlBundle\Http\ReceivedAuthnRequestPost;

class ReceivedAuthnRequestPostTest extends TestCase
{
    /**
     * @test
     */
    public function it_can_decode_a_signed_saml_request(): void
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
    public function it_can_decode_a_signed_saml_request_from_adfs_origin(): void
    {
        $samlRequest = str_replace(PHP_EOL, '', file_get_contents(__DIR__ . '/Resources/valid-signed-adfs.xml'));
        $parameters = [
            'SAMLRequest' => base64_encode($samlRequest),
            'RelayState' => '/index.php',
        ];
        $parsed = ReceivedAuthnRequestPost::parse($parameters);
        $this->assertInstanceOf(ReceivedAuthnRequestPost::class, $parsed);
    }

    /**
     * @test
     */
    public function it_can_decode_an_usigned_saml_request(): void
    {
        $samlRequest = str_replace(PHP_EOL, '', file_get_contents(__DIR__ . '/Resources/valid-unsigned.xml'));
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
    public function it_rejects_malformed_saml_request(): void
    {
        $this->expectExceptionMessage("Failed decoding SAML request, did not receive a valid base64 string");
        $this->expectException(InvalidRequestException::class);
        $parameters = [
            'SAMLRequest' => 'this=notvalid==',
            'RelayState' => '/index.php',
        ];
        ReceivedAuthnRequestPost::parse($parameters);
    }
}
