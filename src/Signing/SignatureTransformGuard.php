<?php declare(strict_types=1);

/**
 * Copyright 2026 SURFnet bv
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

namespace Surfnet\SamlBundle\Signing;

use DOMDocument;
use DOMXPath;
use RuntimeException;
use Surfnet\SamlBundle\Http\Exception\SignatureValidationFailedException;

/**
 * Rejects XML-DSig `<ds:Transform>` algorithms that are not needed for SAML 2.0 signature
 * verification, before the document reaches simplesamlphp/saml2's signature processing.
 *
 * simplesamlphp/saml2 <=4.20.2 (and the underlying robrichards/xmlseclibs it uses) has no
 * upstream patch for GHSA-5cjr-mxj5-wmrx: an attacker-controlled `<ds:Transform
 * Algorithm="...xpath-19991116">` element executes an arbitrary, attacker-supplied XPath
 * expression during signature-reference canonicalization, which can be used for a Denial of
 * Service. This guard implements the same mitigation the advisory describes ("restrict
 * transforms to only the transform-algorithms mentioned in the SAML 2.0 Core Specifications")
 * directly, since no patched release of the v4 line exists or is planned. simplesamlphp/saml2
 * v5+/v6+ fix this internally but are a ground-up rewrite without the SP/IdP response
 * processing this bundle depends on, so are not a viable upgrade path yet.
 *
 * A SAML message can carry independently signed Response and Assertion elements, each with
 * their own `<ds:Signature>`/`<ds:Transform>` chain, so this scans the whole document rather
 * than a single signature node.
 */
final class SignatureTransformGuard
{
    /**
     * The only Transform algorithms simplesamlphp/saml2's response/assertion signature
     * verification legitimately needs to process. Anything else is rejected outright.
     */
    private const ALLOWED_TRANSFORM_ALGORITHMS = [
        'http://www.w3.org/2000/09/xmldsig#enveloped-signature',
        'http://www.w3.org/2001/10/xml-exc-c14n#',
        'http://www.w3.org/2001/10/xml-exc-c14n#WithComments',
        'http://www.w3.org/TR/2001/REC-xml-c14n-20010315',
        'http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments',
    ];

    public static function assertNoForbiddenTransforms(DOMDocument $document): void
    {
        $xpath = new DOMXPath($document);
        $nodes = $xpath->query("//*[local-name()='Transform']");
        if ($nodes === false) {
            throw new RuntimeException('Failed to evaluate XPath while scanning for signature transforms');
        }

        foreach ($nodes as $node) {
            $algorithm = $node->attributes?->getNamedItem('Algorithm')?->nodeValue;
            if ($algorithm === null || in_array($algorithm, self::ALLOWED_TRANSFORM_ALGORITHMS, true)) {
                continue;
            }

            throw new SignatureValidationFailedException(sprintf(
                'Rejected SAML message: contains a forbidden XML signature Transform algorithm "%s"'
                . ' (see GHSA-5cjr-mxj5-wmrx)',
                $algorithm
            ));
        }
    }
}
