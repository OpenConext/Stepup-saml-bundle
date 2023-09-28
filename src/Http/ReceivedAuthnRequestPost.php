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

namespace Surfnet\SamlBundle\Http;

use RobRichards\XMLSecLibs\XMLSecurityKey;
use Surfnet\SamlBundle\Http\Exception\InvalidRequestException;
use Surfnet\SamlBundle\SAML2\ReceivedAuthnRequest;

final class ReceivedAuthnRequestPost implements SignatureVerifiable
{
    public const PARAMETER_REQUEST = 'SAMLRequest';
    public const PARAMETER_RELAY_STATE = 'RelayState';

    /**
     * @var string|null
     */
    private $relayState;

    private ?ReceivedAuthnRequest $receivedRequest = null;

    /**
     * @param string $samlRequest
     */
    private function __construct(private $samlRequest)
    {
    }

    /**
     * @return ReceivedAuthnRequestPost
     *
     * @SuppressWarnings(PHPMD.CyclomaticComplexity) Extensive validation
     * @SuppressWarnings(PHPMD.NPathComplexity) Extensive validation
     */
    public static function parse(array $parameters): self
    {
        if (base64_decode((string) $parameters[self::PARAMETER_REQUEST], true) === false) {
            throw new InvalidRequestException('Failed decoding SAML request, did not receive a valid base64 string');
        }

        $parsed = new self($parameters[self::PARAMETER_REQUEST]);

        if (isset($parameters[self::PARAMETER_RELAY_STATE])) {
            $parsed->relayState = $parameters[self::PARAMETER_RELAY_STATE];
        }

        $decoded = $parsed->getDecodedSamlRequest();
        $request = ReceivedAuthnRequest::from($decoded);

        $parsed->receivedRequest = $request;

        // Return AuthnRequest
        return $parsed;
    }

    /**
     * @return bool
     */
    public function hasRelayState(): bool
    {
        return $this->relayState !== null;
    }

    /**
     * @return string
     */
    public function getDecodedSamlRequest(): string|bool
    {
        return base64_decode($this->samlRequest);
    }

    /**
     * @return string
     */
    public function getSamlRequest()
    {
        return $this->samlRequest;
    }

    /**
     * @return null|string
     */
    public function getRelayState()
    {
        return $this->relayState;
    }

    /**
     * @param XMLSecurityKey $key
     * @return bool
     * @throws \Exception when signature is invalid (@see SAML2\Utils::validateSignature)
     */
    public function verify(XMLSecurityKey $key): bool
    {
        return $this->receivedRequest->verify($key);
    }
}
