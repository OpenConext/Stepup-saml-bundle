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
use SAML2_AuthnRequest;
use SAML2_DOMDocumentFactory;
use stdClass;
use Surfnet\SamlBundle\Exception\RuntimeException;
use Surfnet\SamlBundle\Http\Exception\InvalidReceivedAuthnRequestQueryStringException;
use Surfnet\SamlBundle\Http\Exception\InvalidRequestException;
use Surfnet\SamlBundle\Http\ReceivedAuthnRequestQueryString;

class ReceivedAuthnRequestQueryStringTest extends TestCase
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
     * @test
     * @group AuthnRequest
     *
     * @dataProvider nonOrEmptyStringProvider
     * @param $nonOrEmptyString
     */
    public function a_received_authn_request_query_string_cannot_be_parsed_from_non_or_empty_strings($nonOrEmptyString)
    {
        $this->setExpectedException(
            InvalidReceivedAuthnRequestQueryStringException::class,
            'expected a non-empty string'
        );

        $query = ReceivedAuthnRequestQueryString::parse($nonOrEmptyString);
    }

    /**
     * @test
     * @group AuthnRequest
     */
    public function a_received_authn_request_query_string_cannot_be_parsed_from_a_request_uri_without_a_query_string_separator()
    {
        $this->setExpectedException(
            InvalidReceivedAuthnRequestQueryStringException::class,
            'does not contain a query string separator'
        );

        $query = ReceivedAuthnRequestQueryString::parse('https://my-service-provider.example');
    }

    /**
     * @test
     * @group AuthnRequest
     */
    public function a_received_authn_request_query_string_must_contain_valid_key_value_pairs()
    {
        $this->setExpectedException(
            InvalidReceivedAuthnRequestQueryStringException::class,
            'does not contain a valid key-value pair'
        );

        $query = ReceivedAuthnRequestQueryString::parse('https://my-service-provider.example?no-value');
    }

    /**
     * @test
     * @group AuthnRequest
     *
     * @dataProvider queryStringWithRepeatedSamlParametersProvider
     * @param $doubleParameterName
     * @param $queryStringWithDoubleParameter
     */
    public function a_received_authn_request_query_string_cannot_contain_a_saml_parameter_twice(
        $doubleParameterName, $queryStringWithDoubleParameter
    ) {
        $this->setExpectedException(
            InvalidReceivedAuthnRequestQueryStringException::class,
            sprintf('parameter "%s" already present', $doubleParameterName)
        );

        $query = ReceivedAuthnRequestQueryString::parse($queryStringWithDoubleParameter);
    }

    /**
     * @test
     * @group AuthnRequest
     */
    public function a_received_authn_request_query_string_must_contain_a_saml_request()
    {
        $this->setExpectedException(
            InvalidReceivedAuthnRequestQueryStringException::class,
            sprintf('parameter "%s" not found', ReceivedAuthnRequestQueryString::PARAMETER_REQUEST)
        );

        $queryStringWithoutSamlRequest = 
            '?' . ReceivedAuthnRequestQueryString::PARAMETER_SIGNATURE . '=' . base64_encode('signature')
            . '&' . ReceivedAuthnRequestQueryString::PARAMETER_SIGNATURE_ALGORITHM . '=signature-algorithm';

        $query = ReceivedAuthnRequestQueryString::parse(
            'https://my-service-provider.example' . $queryStringWithoutSamlRequest
        );
    }

    /**
     * @test
     * @group AuthnRequest
     */
    public function a_received_authn_request_query_string_cannot_contain_a_signature_algorithm_without_a_signature()
    {
        $this->setExpectedException(
            InvalidReceivedAuthnRequestQueryStringException::class,
            'contains a signature algorithm but not a signature'
        );

        $queryStringWithSignatureAlgorithmWithoutSignature = '?' . ReceivedAuthnRequestQueryString::PARAMETER_REQUEST . '=saml-request'
            . '&' . ReceivedAuthnRequestQueryString::PARAMETER_SIGNATURE_ALGORITHM . '=signature-algorithm';

        $query = ReceivedAuthnRequestQueryString::parse(
            'https://my-service-provider.example' . $queryStringWithSignatureAlgorithmWithoutSignature
        );
    }

    /**
     * @test
     * @group AuthnRequest
     */
    public function a_received_authn_request_query_string_cannot_contain_a_signature_without_a_signature_algorithm()
    {
        $this->setExpectedException(
            InvalidReceivedAuthnRequestQueryStringException::class,
            'contains a signature but not a signature algorithm'
        );

        $queryStringWithSignatureWithoutSignatureAlgorithm =
            '?' . ReceivedAuthnRequestQueryString::PARAMETER_REQUEST . '=saml-request'
            . '&' . ReceivedAuthnRequestQueryString::PARAMETER_SIGNATURE . '=' . base64_encode('signature');

        $query = ReceivedAuthnRequestQueryString::parse(
            'https://my-service-provider.example' . $queryStringWithSignatureWithoutSignatureAlgorithm
        );
    }

    /**
     * @test
     * @group AuthnRequest
     */
    public function a_received_authn_request_query_string_cannot_contain_a_signature_that_is_not_properly_base64_encoded()
    {
        $this->setExpectedException(
            InvalidReceivedAuthnRequestQueryStringException::class,
            'signature is not base64 encoded correctly'
        );

        $queryStringWithSignatureWithoutSignatureAlgorithm = '?' . ReceivedAuthnRequestQueryString::PARAMETER_REQUEST . '=saml-request'
            . '&' . ReceivedAuthnRequestQueryString::PARAMETER_SIGNATURE . '=not-encoded-signature';

        $query = ReceivedAuthnRequestQueryString::parse(
            'https://my-service-provider.example' . $queryStringWithSignatureWithoutSignatureAlgorithm
        );
    }

    /**
     * @test
     * @group AuthnRequest
     */
    public function a_received_authn_request_query_string_can_be_converted_to_a_signed_query_string()
    {
        $queryString = ReceivedAuthnRequestQueryString::PARAMETER_REQUEST . '=encoded-saml-request'
            . '&' . ReceivedAuthnRequestQueryString::PARAMETER_RELAY_STATE . '=relay-state'
            . '&' . ReceivedAuthnRequestQueryString::PARAMETER_SIGNATURE . '=' . base64_encode('signature')
            . '&' . ReceivedAuthnRequestQueryString::PARAMETER_SIGNATURE_ALGORITHM . '=signature-algorithm';

        $query = ReceivedAuthnRequestQueryString::parse('https://my-service-provider.example?' . $queryString);

        $signedQueryString = $query->getSignedQueryString();

        $this->assertEquals($queryString, $signedQueryString);
    }

    /**
     * @test
     * @group AuthnRequest
     */
    public function query_parameters_that_are_not_used_for_a_saml_message_are_ignored_when_creating_a_signed_query_string()
    {
        $arbitraryParameterToIgnore = 'arbitraryParameter=this-should-be-ignored';

        $queryString = ReceivedAuthnRequestQueryString::PARAMETER_REQUEST . '=encoded-saml-request'
            . '&' . ReceivedAuthnRequestQueryString::PARAMETER_RELAY_STATE . '=relay-state'
            . '&' . ReceivedAuthnRequestQueryString::PARAMETER_SIGNATURE . '=' . base64_encode('signature')
            . '&' . ReceivedAuthnRequestQueryString::PARAMETER_SIGNATURE_ALGORITHM . '=signature-algorithm';

        $query = ReceivedAuthnRequestQueryString::parse(
            'https://my-service-provider.example?' . $queryString . '&' . $arbitraryParameterToIgnore
        );

        $signedQueryString = $query->getSignedQueryString();

        $this->assertNotEquals(
            $queryString . '&' . $arbitraryParameterToIgnore,
            $signedQueryString,
            'The signed query string should not contain parameters that are irrelevant for the AuthnRequest'
        );
    }

    /**
     * @test
     * @group AuthnRequest
     */
    public function query_parameters_that_are_not_used_for_a_saml_message_are_ignored_when_creating_a_signable_query_string()
    {
        $arbitraryParameterToIgnore = 'arbitraryParameter=this-should-be-ignored';

        $queryString = ReceivedAuthnRequestQueryString::PARAMETER_REQUEST . '=encoded-saml-request'
            . '&' . ReceivedAuthnRequestQueryString::PARAMETER_RELAY_STATE . '=relay-state'
            . '&' . ReceivedAuthnRequestQueryString::PARAMETER_SIGNATURE . '=' . base64_encode('signature')
            . '&' . ReceivedAuthnRequestQueryString::PARAMETER_SIGNATURE_ALGORITHM . '=signature-algorithm';

        $query = ReceivedAuthnRequestQueryString::parse(
            'https://my-service-provider.example?' . $queryString . '&' . $arbitraryParameterToIgnore
        );

        $signableQueryString = $query->getSignableQueryString();

        $this->assertNotEquals(
            $queryString . '&' . $arbitraryParameterToIgnore,
            $signableQueryString,
            'The signable query string should not contain parameters that are irrelevant for the AuthnRequest'
        );
    }

    /**
     * @test
     * @group AuthnRequest
     */
    public function cannot_get_a_signable_query_string_from_a_received_authn_request_query_string_if_has_no_signature_algorithm()
    {
        $this->setExpectedException(RuntimeException::class, 'SigAlg missing');

        $queryStringWithoutSignatureAndSignatureAlgorithm =
            ReceivedAuthnRequestQueryString::PARAMETER_REQUEST . '=encoded-saml-request'
            . '&' . ReceivedAuthnRequestQueryString::PARAMETER_RELAY_STATE . '=relay-state';

        $query = ReceivedAuthnRequestQueryString::parse(
            'https://my-service-provider.example?' . $queryStringWithoutSignatureAndSignatureAlgorithm
        );

        $query->getSignableQueryString();
    }

    /**
     * @test
     * @group AuthnRequest
     */
    public function a_correctly_ordered_signable_query_string_can_be_acquired_from_a_received_authn_request_query_string()
    {
        $signedQueryString =
            ReceivedAuthnRequestQueryString::PARAMETER_REQUEST . '=encoded-saml-request'
            . '&' . ReceivedAuthnRequestQueryString::PARAMETER_SIGNATURE . '=' . base64_encode('signature')
            . '&' . ReceivedAuthnRequestQueryString::PARAMETER_SIGNATURE_ALGORITHM . '=signature-algorithm'
            . '&' . ReceivedAuthnRequestQueryString::PARAMETER_RELAY_STATE . '=relay-state';

        $query = ReceivedAuthnRequestQueryString::parse('https://my-service-provider.example?' . $signedQueryString);

        $expectedSignableQueryString =
            ReceivedAuthnRequestQueryString::PARAMETER_REQUEST . '=encoded-saml-request'
            . '&' . ReceivedAuthnRequestQueryString::PARAMETER_RELAY_STATE . '=relay-state'
            . '&' . ReceivedAuthnRequestQueryString::PARAMETER_SIGNATURE_ALGORITHM . '=signature-algorithm';

        $actualSignableQueryString = $query->getSignableQueryString();

        $this->assertEquals(
            $expectedSignableQueryString,
            $actualSignableQueryString,
            'A correctly ordered signable query string should be acquired from a received AuthnRequest query string,'
            . ' but it was not'
        );
    }

    /**
     * @test
     * @group AuthnRequest
     */
    public function a_decoded_signature_can_be_acquired_from_a_received_authn_request_query_string()
    {
        $signature = 'signature';

        $signedQueryString =
            ReceivedAuthnRequestQueryString::PARAMETER_REQUEST . '=encoded-saml-request'
            . '&' . ReceivedAuthnRequestQueryString::PARAMETER_SIGNATURE . '=' . base64_encode($signature)
            . '&' . ReceivedAuthnRequestQueryString::PARAMETER_SIGNATURE_ALGORITHM . '=signature-algorithm';

        $query = ReceivedAuthnRequestQueryString::parse('https://my-service-provider.example?' . $signedQueryString);

        $decodedSignature = $query->getDecodedSignature();

        $this->assertEquals(
            $signature,
            $decodedSignature,
            'The correct decoded signature could not be acquired from the received AuthnRequest query string'
        );
    }

    /**
     * @test
     * @group AuthnRequest
     */
    public function a_decoded_saml_request_can_be_acquired_from_a_received_authn_request_query_string()
    {
        $domDocument          = SAML2_DOMDocumentFactory::fromString($this->authRequestNoSubject);
        $unsignedAuthnRequest = SAML2_AuthnRequest::fromXML($domDocument->firstChild);

        $requestAsXml   = $unsignedAuthnRequest->toUnsignedXML()->ownerDocument->saveXML();
        $encodedRequest = base64_encode(gzdeflate($requestAsXml));

        $rawQuery = ReceivedAuthnRequestQueryString::PARAMETER_REQUEST . '=' . $encodedRequest;
        $requestUri = 'https://my-service-provider.example?' . $rawQuery;

        $query = ReceivedAuthnRequestQueryString::parse($requestUri);
        $decodedRequest = $query->getDecodedSamlRequest();

        $this->assertEquals(
            $requestAsXml,
            $decodedRequest,
            'The correct decoded SAMLRequest could not be acquired from the received AuthnRequest query string'
        );
    }

    /**
     * @test
     * @group AuthnRequest
     */
    public function a_saml_request_cannot_be_decoded_from_a_received_authn_request_query_string_if_it_was_not_properly_base64_encoded()
    {
        $this->setExpectedException(InvalidRequestException::class, 'did not receive a valid base64 string');

        $notEncodedRequest = 'this-is-not-encoded';

        $rawQuery = ReceivedAuthnRequestQueryString::PARAMETER_REQUEST . '=' . $notEncodedRequest;
        $requestUri = 'https://my-service-provider.example?' . $rawQuery;

        $query = ReceivedAuthnRequestQueryString::parse($requestUri);
        $decodedRequest = $query->getDecodedSamlRequest();
    }

    /**
     * @test
     * @group AuthnRequest
     */
    public function a_saml_request_cannot_be_decoded_from_a_received_authn_request_query_string_if_it_was_not_properly_gzipped()
    {
        $this->setExpectedException(InvalidRequestException::class, 'Failed inflating SAML Request');

        $notGzippedRequest = base64_encode('this-is-not-encoded');

        $rawQuery = ReceivedAuthnRequestQueryString::PARAMETER_REQUEST . '=' . $notGzippedRequest;
        $requestUri = 'https://my-service-provider.example?' . $rawQuery;

        $query = ReceivedAuthnRequestQueryString::parse($requestUri);
        $decodedRequest = $query->getDecodedSamlRequest();
    }

    /**
     * @test
     * @group AuthnRequest
     */
    public function parameters_can_be_queried_from_the_received_authn_request_query()
    {
        $samlRequest = 'encoded-saml-request';
        $relayState = 'relay-state';
        $signatureAlgorithm = 'signature-algorithm';
        $signature = 'signature';

        $rawQuery =
            ReceivedAuthnRequestQueryString::PARAMETER_REQUEST . '=' . $samlRequest
            . '&' . ReceivedAuthnRequestQueryString::PARAMETER_RELAY_STATE . '=' . $relayState
            . '&' . ReceivedAuthnRequestQueryString::PARAMETER_SIGNATURE . '=' . $signature
            . '&' . ReceivedAuthnRequestQueryString::PARAMETER_SIGNATURE_ALGORITHM . '=' . $signatureAlgorithm;

        $queryString = ReceivedAuthnRequestQueryString::parse('https://my-service-provider.example?' . $rawQuery);

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
            'Could not get the correct SigAlg from the query string');
        $this->assertEquals(
            $signature,
            $queryString->getSignature(),
            'Could not get the correct Signature from the query string'
        );
    }

    /**
     * @return array
     */
    public function nonOrEmptyStringProvider()
    {
        return [
            'empty string' => [''],
            'string with spaces' => ['   '],
            'integer' => [123],
            'float' => [1.23],
            'object' => [new stdClass()],
            'array' => [[1, 2, 3]],
            'boolean' => [true]
        ];
    }

    /**
     * @return array
     */
    public function queryStringWithRepeatedSamlParametersProvider()
    {
        $basicQueryString = $basicQueryString = ReceivedAuthnRequestQueryString::PARAMETER_REQUEST . '=encoded-saml-request'
            . '&' . ReceivedAuthnRequestQueryString::PARAMETER_RELAY_STATE . '=relay-state'
            . '&' . ReceivedAuthnRequestQueryString::PARAMETER_SIGNATURE . '=' . base64_encode('signature')
            . '&' . ReceivedAuthnRequestQueryString::PARAMETER_SIGNATURE_ALGORITHM . '=signature-algorithm';

        $uri = 'https://some-service-provider.org?' . $basicQueryString;

        return [
            ReceivedAuthnRequestQueryString::PARAMETER_REQUEST             => [
                ReceivedAuthnRequestQueryString::PARAMETER_REQUEST,
                $uri . '&' . ReceivedAuthnRequestQueryString::PARAMETER_REQUEST . '=second-encoded-saml-request',
            ],
            ReceivedAuthnRequestQueryString::PARAMETER_RELAY_STATE         => [
                ReceivedAuthnRequestQueryString::PARAMETER_RELAY_STATE,
                $uri . '&' . ReceivedAuthnRequestQueryString::PARAMETER_RELAY_STATE . '=second-relay-state',
            ],
            ReceivedAuthnRequestQueryString::PARAMETER_SIGNATURE           => [
                ReceivedAuthnRequestQueryString::PARAMETER_SIGNATURE,
                $uri .'&' . ReceivedAuthnRequestQueryString::PARAMETER_SIGNATURE . '=' . base64_encode('signature'),
            ],
            ReceivedAuthnRequestQueryString::PARAMETER_SIGNATURE_ALGORITHM => [
                ReceivedAuthnRequestQueryString::PARAMETER_SIGNATURE_ALGORITHM,
                $uri .'&' . ReceivedAuthnRequestQueryString::PARAMETER_SIGNATURE_ALGORITHM . '=signature-algorithm',
            ],
        ];
    }
}
