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

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Group;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use SAML2\AuthnRequest as SAML2AuthnRequest;
use SAML2\DOMDocumentFactory;
use stdClass;
use Surfnet\SamlBundle\Http\Exception\InvalidReceivedAuthnRequestQueryStringException;
use Surfnet\SamlBundle\Http\Exception\InvalidRequestException;
use Surfnet\SamlBundle\Http\ReceivedAuthnRequestQueryString;

class ReceivedAuthnRequestQueryStringTest extends TestCase
{
    private string $authRequestNoSubject = <<<AUTHNREQUEST_NO_SUBJECT
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
     *
     * @param $nonOrEmptyString
     */
    #[Test]
    #[DataProvider('emptyStringProvider')]
    #[Group('AuthnRequest')]
    public function a_received_authn_request_query_string_cannot_be_parsed_from_empty_strings(string $nonOrEmptyString): void
    {
        $this->expectException('\\' . InvalidReceivedAuthnRequestQueryStringException::class);
        $this->expectExceptionMessage('expected a non-empty string');

        ReceivedAuthnRequestQueryString::parse($nonOrEmptyString);
    }

    #[Test]
    #[Group('AuthnRequest')]
    public function a_received_authn_request_query_string_must_contain_valid_key_value_pairs(): void
    {
        $this->expectException('\\' . InvalidReceivedAuthnRequestQueryStringException::class);
        $this->expectExceptionMessage('does not contain a valid key-value pair');

        ReceivedAuthnRequestQueryString::parse('a-key-without-a-value');
    }

    #[Test]
    #[Group('AuthnRequest')]
    public function a_received_authn_request_query_string_must_contain_a_base64_encoded_saml_request(): void
    {
        $this->expectException('\\' . InvalidRequestException::class);
        $this->expectExceptionMessage('did not receive a valid base64 string');

        $notEncodedRequest = 'non-encoded-string';

        $rawQuery = ReceivedAuthnRequestQueryString::PARAMETER_REQUEST . '=' . urlencode($notEncodedRequest);

        ReceivedAuthnRequestQueryString::parse($rawQuery);
    }

    /**
     * @param $doubleParameterName
     * @param $queryStringWithDoubleParameter
     */
    #[Test]
    #[DataProvider('queryStringWithRepeatedSamlParametersProvider')]
    #[Group('AuthnRequest')]
    public function a_received_authn_request_query_string_cannot_contain_a_saml_parameter_twice(
        string $doubleParameterName,
        string $queryStringWithDoubleParameter
    ): void {
        $this->expectException('\\' . InvalidReceivedAuthnRequestQueryStringException::class);
        $this->expectExceptionMessage(sprintf('parameter "%s" already present', $doubleParameterName));

        ReceivedAuthnRequestQueryString::parse($queryStringWithDoubleParameter);
    }

    #[Test]
    #[Group('AuthnRequest')]
    public function a_received_authn_request_query_string_must_contain_a_saml_request(): void
    {
        $this->expectException('\\' . InvalidReceivedAuthnRequestQueryStringException::class);
        $this->expectExceptionMessage(sprintf('parameter "%s" not found', ReceivedAuthnRequestQueryString::PARAMETER_REQUEST));

        $queryStringWithoutSamlRequest =
            '?' . ReceivedAuthnRequestQueryString::PARAMETER_SIGNATURE . '=' . urlencode(base64_encode('signature'))
            . '&' . ReceivedAuthnRequestQueryString::PARAMETER_SIGNATURE_ALGORITHM . '=signature-algorithm';

        ReceivedAuthnRequestQueryString::parse($queryStringWithoutSamlRequest);
    }

    #[Test]
    #[Group('AuthnRequest')]
    public function a_received_authn_request_query_string_cannot_contain_a_signature_algorithm_without_a_signature(): void
    {
        $this->expectException('\\' . InvalidReceivedAuthnRequestQueryStringException::class);
        $this->expectExceptionMessage('contains a signature algorithm but not a signature');

        $queryStringWithSignatureAlgorithmWithoutSignature =
            '?' . ReceivedAuthnRequestQueryString::PARAMETER_REQUEST . '=' . urlencode(base64_encode('saml-request'))
            . '&' . ReceivedAuthnRequestQueryString::PARAMETER_SIGNATURE_ALGORITHM . '=signature-algorithm';

        ReceivedAuthnRequestQueryString::parse($queryStringWithSignatureAlgorithmWithoutSignature);
    }

    #[Test]
    #[Group('AuthnRequest')]
    public function a_received_authn_request_query_string_cannot_contain_a_signature_without_a_signature_algorithm(): void
    {
        $this->expectException('\\' . InvalidReceivedAuthnRequestQueryStringException::class);
        $this->expectExceptionMessage('contains a signature but not a signature algorithm');

        $queryStringWithSignatureWithoutSignatureAlgorithm =
            '?' . ReceivedAuthnRequestQueryString::PARAMETER_REQUEST . '=' . urlencode(base64_encode('saml-request'))
            . '&' . ReceivedAuthnRequestQueryString::PARAMETER_SIGNATURE . '=' . urlencode(base64_encode('signature'));

        ReceivedAuthnRequestQueryString::parse($queryStringWithSignatureWithoutSignatureAlgorithm);
    }

    #[Test]
    #[Group('AuthnRequest')]
    public function a_received_authn_request_query_string_cannot_contain_a_signature_that_is_not_properly_base64_encoded(): void
    {
        $this->expectException('\\' . InvalidReceivedAuthnRequestQueryStringException::class);
        $this->expectExceptionMessage('signature is not base64 encoded correctly');

        $queryStringWithSignatureWithoutSignatureAlgorithm =
            '?' . ReceivedAuthnRequestQueryString::PARAMETER_REQUEST . '=' . urlencode(base64_encode('saml-request'))
            . '&' . ReceivedAuthnRequestQueryString::PARAMETER_SIGNATURE . '=not-encoded-signature'
            . '&' . ReceivedAuthnRequestQueryString::PARAMETER_SIGNATURE_ALGORITHM . '=sig-alg';

        ReceivedAuthnRequestQueryString::parse($queryStringWithSignatureWithoutSignatureAlgorithm);
    }

    #[Test]
    #[Group('AuthnRequest')]
    public function a_signed_query_string_can_be_acquired_from_a_received_authn_request_query_string(): void
    {
        $expectedSignedQueryString = ReceivedAuthnRequestQueryString::PARAMETER_REQUEST . '=' . urlencode(base64_encode('saml-request'))
            . '&' . ReceivedAuthnRequestQueryString::PARAMETER_RELAY_STATE . '=relay-state'
            . '&' . ReceivedAuthnRequestQueryString::PARAMETER_SIGNATURE_ALGORITHM . '=signature-algorithm';
        $receivedQueryString = $expectedSignedQueryString
            . '&' . ReceivedAuthnRequestQueryString::PARAMETER_SIGNATURE . '=' . urlencode(base64_encode('signature'));

        $query = ReceivedAuthnRequestQueryString::parse($receivedQueryString);

        $actualQueryString = $query->getSignedQueryString();

        $this->assertEquals($expectedSignedQueryString, $actualQueryString);
    }

    #[Test]
    #[Group('AuthnRequest')]
    public function query_parameters_that_are_not_used_for_a_saml_message_are_ignored_when_creating_a_signed_query_string(): void
    {
        $arbitraryParameterToIgnore = 'arbitraryParameter=this-should-be-ignored';

        $queryString =
            ReceivedAuthnRequestQueryString::PARAMETER_REQUEST . '=' . urlencode(base64_encode('saml-request'))
            . '&' . ReceivedAuthnRequestQueryString::PARAMETER_RELAY_STATE . '=relay-state'
            . '&' . ReceivedAuthnRequestQueryString::PARAMETER_SIGNATURE . '=' . urlencode(base64_encode('signature'))
            . '&' . ReceivedAuthnRequestQueryString::PARAMETER_SIGNATURE_ALGORITHM . '=signature-algorithm';

        $query = ReceivedAuthnRequestQueryString::parse($queryString . '&' . $arbitraryParameterToIgnore);

        $signedQueryString = $query->getSignedQueryString();

        $this->assertNotEquals(
            $queryString . '&' . $arbitraryParameterToIgnore,
            $signedQueryString,
            'The signed query string should not contain parameters that are irrelevant for the AuthnRequest'
        );
    }

    #[Test]
    #[Group('AuthnRequest')]
    public function a_decoded_signature_can_be_acquired_from_a_received_authn_request_query_string(): void
    {
        $signature = 'signature';

        $signedQueryString =
            ReceivedAuthnRequestQueryString::PARAMETER_REQUEST . '=' . urlencode(base64_encode('saml-request'))
            . '&' . ReceivedAuthnRequestQueryString::PARAMETER_SIGNATURE . '=' . urlencode(base64_encode($signature))
            . '&' . ReceivedAuthnRequestQueryString::PARAMETER_SIGNATURE_ALGORITHM . '=signature-algorithm';

        $query = ReceivedAuthnRequestQueryString::parse($signedQueryString);

        $decodedSignature = $query->getDecodedSignature();

        $this->assertEquals(
            $signature,
            $decodedSignature,
            'The correct decoded signature could not be acquired from the received AuthnRequest query string'
        );
    }

    #[Test]
    #[Group('AuthnRequest')]
    public function a_decoded_saml_request_can_be_acquired_from_a_received_authn_request_query_string(): void
    {
        $domDocument          = DOMDocumentFactory::fromString($this->authRequestNoSubject);
        $unsignedAuthnRequest = SAML2AuthnRequest::fromXML($domDocument->firstChild);

        $requestAsXml   = $unsignedAuthnRequest->toUnsignedXML()->ownerDocument->saveXML();
        $encodedRequest = base64_encode(gzdeflate($requestAsXml));

        $rawQuery = ReceivedAuthnRequestQueryString::PARAMETER_REQUEST . '=' . urlencode($encodedRequest);

        $query = ReceivedAuthnRequestQueryString::parse($rawQuery);
        $decodedRequest = $query->getDecodedSamlRequest();

        $this->assertEquals(
            $requestAsXml,
            $decodedRequest,
            'The correct decoded SAMLRequest could not be acquired from the received AuthnRequest query string'
        );
    }

    #[Test]
    #[Group('AuthnRequest')]
    public function a_saml_request_cannot_be_decoded_from_a_received_authn_request_query_string_if_it_was_not_properly_gzipped(): void
    {
        $this->expectException('\\' . InvalidRequestException::class);
        $this->expectExceptionMessage('Failed inflating SAML Request');

        $notGzippedRequest = urlencode(base64_encode('this-is-not-gzipped'));

        $rawQuery = ReceivedAuthnRequestQueryString::PARAMETER_REQUEST . '=' . $notGzippedRequest;

        $query = ReceivedAuthnRequestQueryString::parse($rawQuery);
        $query->getDecodedSamlRequest();
    }

    #[Test]
    #[Group('AuthnRequest')]
    public function parameters_can_be_queried_from_the_received_authn_request_query(): void
    {
        $samlRequest = urlencode(base64_encode('encoded-saml-request'));
        $relayState = 'relay-state';
        $signatureAlgorithm = 'signature-algorithm';
        $signature = urlencode(base64_encode('signature'));

        $rawQuery =
            ReceivedAuthnRequestQueryString::PARAMETER_REQUEST . '=' . $samlRequest
            . '&' . ReceivedAuthnRequestQueryString::PARAMETER_RELAY_STATE . '=' . $relayState
            . '&' . ReceivedAuthnRequestQueryString::PARAMETER_SIGNATURE . '=' . $signature
            . '&' . ReceivedAuthnRequestQueryString::PARAMETER_SIGNATURE_ALGORITHM . '=' . $signatureAlgorithm;

        $queryString = ReceivedAuthnRequestQueryString::parse($rawQuery);

        $this->assertEquals(
            $samlRequest,
            $queryString->getSamlRequest(),
            'Could not get the correct SAMLRequest from the query string'
        );
        $this->assertEquals(
            $relayState,
            $queryString->getRelayState(),
            'Could not get the correct RelayState from the query string'
        );
        $this->assertEquals(
            $signatureAlgorithm,
            $queryString->getSignatureAlgorithm(),
            'Could not get the correct SigAlg from the query string'
        );
        $this->assertEquals(
            $signature,
            $queryString->getSignature(),
            'Could not get the correct Signature from the query string'
        );
    }

    public static function emptyStringProvider(): array
    {
        return [
            'empty string' => [''],
            'string with spaces' => ['   ']
        ];
    }
    public function nonStringProvider(): array
    {
        return [
            'integer' => [123],
            'float' => [1.23],
            'object' => [new stdClass()],
            'array' => [[1, 2, 3]],
            'boolean' => [true]
        ];
    }

    public static function queryStringWithRepeatedSamlParametersProvider(): array
    {
        $queryString = ReceivedAuthnRequestQueryString::PARAMETER_REQUEST . '=' . urlencode(base64_encode('saml-request'))
            . '&' . ReceivedAuthnRequestQueryString::PARAMETER_RELAY_STATE . '=relay-state'
            . '&' . ReceivedAuthnRequestQueryString::PARAMETER_SIGNATURE . '=' . urlencode(base64_encode('signature'))
            . '&' . ReceivedAuthnRequestQueryString::PARAMETER_SIGNATURE_ALGORITHM . '=signature-algorithm';

        return [
            ReceivedAuthnRequestQueryString::PARAMETER_REQUEST             => [
                ReceivedAuthnRequestQueryString::PARAMETER_REQUEST,
                $queryString . '&' . ReceivedAuthnRequestQueryString::PARAMETER_REQUEST . '=second-encoded-saml-request',
            ],
            ReceivedAuthnRequestQueryString::PARAMETER_RELAY_STATE         => [
                ReceivedAuthnRequestQueryString::PARAMETER_RELAY_STATE,
                $queryString . '&' . ReceivedAuthnRequestQueryString::PARAMETER_RELAY_STATE . '=second-relay-state',
            ],
            ReceivedAuthnRequestQueryString::PARAMETER_SIGNATURE           => [
                ReceivedAuthnRequestQueryString::PARAMETER_SIGNATURE,
                $queryString .'&' . ReceivedAuthnRequestQueryString::PARAMETER_SIGNATURE . '=' . urlencode(base64_encode('signature')),
            ],
            ReceivedAuthnRequestQueryString::PARAMETER_SIGNATURE_ALGORITHM => [
                ReceivedAuthnRequestQueryString::PARAMETER_SIGNATURE_ALGORITHM,
                $queryString .'&' . ReceivedAuthnRequestQueryString::PARAMETER_SIGNATURE_ALGORITHM . '=signature-algorithm',
            ],
        ];
    }
}
