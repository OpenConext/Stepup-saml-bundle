<?php

/**
 * Copyright 2016 SURFnet B.V.
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

namespace Surfnet\SamlBundle\Tests\Component\Signing;

use PHPUnit_Framework_TestCase as TestCase;
use Psr\Log\NullLogger;
use SAML2_AuthnRequest;
use SAML2_Certificate_KeyLoader;
use SAML2_Certificate_X509;
use SAML2_DOMDocumentFactory;
use Surfnet\SamlBundle\SAML2\AuthnRequest;
use Surfnet\SamlBundle\Signing\SignatureVerifier;
use XMLSecurityKey;

class AuthnRequestSigningTest extends TestCase
{
    /**
     * @var string
     */
    private $authRequestNoSubject = <<<AUTHNREQUEST_NO_SUBJECT
<samlp:AuthnRequest
    xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
    xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
    AssertionConsumerServiceIndex="1"
    Destination="https://tiqr.stepup.org/idp/profile/saml2/Redirect/SSO"
    ID="_2b0226190ca1c22de6f66e85f5c95158"
    IssueInstant="2014-09-22T13:42:00Z"
    Version="2.0">
  <saml:Issuer>https://gateway.stepup.org/saml20/sp/metadata</saml:Issuer>
</samlp:AuthnRequest>
AUTHNREQUEST_NO_SUBJECT;

    /**
     * @var string|null
     */
    private $publicKey = null;

    /**
     * @test
     * @group Signing
     */
    public function signatures_are_verified_regardless_of_encoding_used_by_sender(
    )
    {
        $authnRequestWithDefaultEncoding = $this->createSignedAuthnRequest(
            [$this, 'encodeDataToSignWithPhpsHttpBuildQuery']
        );
        $authnRequestWithCustomEncoding  = $this->createSignedAuthnRequest(
            [$this, 'encodeDataToSignWithCustomHttpQueryEncoding']
        );

        $certificate = SAML2_Certificate_X509::createFromCertificateData($this->getPublicKey());

        $signatureVerifier    = new SignatureVerifier(new SAML2_Certificate_KeyLoader, new NullLogger);
        $signatureWithDefaultEncodingIsVerified = $signatureVerifier->isSignedWith(
            $authnRequestWithDefaultEncoding,
            $certificate
        );
        $signatureWithCustomEncodingIsVerified  = $signatureVerifier->isSignedWith(
            $authnRequestWithCustomEncoding,
            $certificate
        );

        $this->assertTrue(
            $signatureWithDefaultEncodingIsVerified,
            'The signature of an AuthnRequest signed using data-to-sign encoded'
            . ' according to RFC1738 should be verifiable, but it isn\'t'
        );
        $this->assertTrue($signatureWithCustomEncodingIsVerified,
            'The signature of an AuthnRequest signed using data-to-sign encoded'.
            ' using a custom encoding should be verifiable, but it isn\'t'
        );
    }

    /**
     * @test
     * @group Signing
     */
    public function signatures_are_not_verified_if_the_data_to_sign_does_not_correspond_with_the_signature_sent()
    {
        $authnRequestWithModifiedDataToSign = $this->createSignedAuthnRequest(
            [$this, 'encodeDataToSignWithPhpsHttpBuildQuery'],
            'this-is-a-custom-signature'
        );

        $certificate = SAML2_Certificate_X509::createFromCertificateData($this->getPublicKey());

        $signatureVerifier   = new SignatureVerifier(new SAML2_Certificate_KeyLoader, new NullLogger);
        $signatureIsVerified = $signatureVerifier->isSignedWith($authnRequestWithModifiedDataToSign, $certificate);

        $this->assertFalse(
            $signatureIsVerified,
            'The signature of an AuthnRequest signed using data-to-sign'
            . ' that does not correspond with how it is represented'
            . ' in the http query should not be verifiable but it is'
        );
    }

    /**
     * @test
     * @group Signing
     */
    public function signatures_are_not_verified_if_the_parameter_order_of_the_sent_query_is_not_correct()
    {
        $authnRequestWithModifiedDataToSign = $this->createSignedAuthnRequest(
            [$this, 'encodeDataToSignUsingIncorrectParameterOrder']
        );

        $certificate = SAML2_Certificate_X509::createFromCertificateData($this->getPublicKey());

        $signatureVerifier   = new SignatureVerifier(new SAML2_Certificate_KeyLoader, new NullLogger);
        $signatureIsVerified = $signatureVerifier->isSignedWith($authnRequestWithModifiedDataToSign, $certificate);

        $this->assertFalse(
            $signatureIsVerified,
            'The signature of an AuthnRequest signed using data-to-sign'
            . ' that corresponds with how it is represented'
            . ' but the data-to-sign is in the wrong order should not be verifiable but it is'
        );
    }

    /**
     * @param array $params
     * @return string
     */
    private function encodeDataToSignWithPhpsHttpBuildQuery(array $params)
    {
        return http_build_query($params);
    }

    /**
     * @param array $params
     * @return string
     */
    private function encodeDataToSignWithCustomHttpQueryEncoding(array $params)
    {
        $encodedParams = http_build_query($params);

        // Use custom encoding to be incompatible with PHP's RFC1738 or RFC3986, to make sure verification issues would
        // arise if we were solely relying on http_build_query internally
        return str_replace('%3A', ':', $encodedParams);
    }

    /**
     * @param array $params
     * @return string
     */
    private function encodeDataToSignUsingIncorrectParameterOrder(array $params)
    {
        return http_build_query(array_reverse($params, true));
    }

    /**
     * @param callable $prepareDataToSign Expects an associative array of data to sign and returns a string to sign
     * @param null|string $customSignature Signature to be used instead of signature to sign data to sign with
     * @return AuthnRequest
     */
    private function createSignedAuthnRequest(
        callable $prepareDataToSign,
        $customSignature = null
    ) {
        $keyData    = file_get_contents(__DIR__.'/../../../Resources/keys/development_privatekey.pem');
        $privateKey = new XMLSecurityKey(XMLSecurityKey::RSA_SHA256, ['type' => 'private']);
        $privateKey->loadKey($keyData);

        $domDocument          = SAML2_DOMDocumentFactory::fromString($this->authRequestNoSubject);
        $unsignedAuthnRequest = SAML2_AuthnRequest::fromXML($domDocument->firstChild);
        $unsignedAuthnRequest->setSignatureKey($privateKey);

        $requestAsXml   = $unsignedAuthnRequest->toUnsignedXML()->ownerDocument->saveXML();
        $encodedRequest = base64_encode(gzdeflate($requestAsXml));
        $queryParams    = [AuthnRequest::PARAMETER_REQUEST => $encodedRequest];

        $queryParams[AuthnRequest::PARAMETER_SIGNATURE_ALGORITHM] = $privateKey->type;

        $toSign = $prepareDataToSign($queryParams);
        if ($customSignature === null) {
            $signature = base64_encode($privateKey->signData($toSign));
        } else {
            $signature = base64_encode($customSignature);
        }
        $httpQuery = $toSign . '&Signature=' . urlencode($signature);

        $saml2AuthnRequest = SAML2_AuthnRequest::fromXML($unsignedAuthnRequest->toUnsignedXML());

        return AuthnRequest::createSigned(
            $saml2AuthnRequest,
            $httpQuery,
            $signature,
            $privateKey->type
        );
    }

    private function getPublicKey()
    {
        if ($this->publicKey === null) {
            $file = file_get_contents(__DIR__.'/../../../Resources/keys/development_publickey.cer');
            $this->publicKey = str_replace(['-----BEGIN CERTIFICATE-----', '-----END CERTIFICATE-----'], '', $file);
        }

        return $this->publicKey;
    }
}
