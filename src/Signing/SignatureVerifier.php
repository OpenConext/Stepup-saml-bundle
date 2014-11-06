<?php

namespace Surfnet\SamlBundle\Signing;

use SAML2_Certificate_Key;
use SAML2_Certificate_KeyLoader as KeyLoader;
use SAML2_Certificate_X509;
use Surfnet\SamlBundle\Entity\ServiceProvider;
use Surfnet\SamlBundle\SAML2\AuthnRequest;
use XMLSecurityKey;

class SignatureVerifier
{
    /**
     * @var \SAML2_Certificate_KeyLoader
     */
    private $keyLoader;

    /**
     * @param KeyLoader       $keyLoader
     */
    public function __construct(KeyLoader $keyLoader)
    {
        $this->keyLoader = $keyLoader;
    }

    /**
     * @param AuthnRequest    $request
     * @param ServiceProvider $serviceProvider
     * @return bool
     */
    public function hasValidSignature(AuthnRequest $request, ServiceProvider $serviceProvider)
    {
        $keys = $this->keyLoader->extractPublicKeys($serviceProvider);

        $x509Keys = $keys->filter(function (SAML2_Certificate_Key $key) {
            return $key instanceof SAML2_Certificate_X509;
        });

        foreach ($x509Keys as $key) {
            if ($this->isSignedWith($request, $key)) {
                return true;
            }
        }

        return false;
    }

    /**
     * @param AuthnRequest           $request
     * @param SAML2_Certificate_X509 $publicKey
     * @return bool
     * @throws \Exception
     */
    public function isSignedWith(AuthnRequest $request, SAML2_Certificate_X509 $publicKey)
    {
        $key = new XMLSecurityKey(XMLSecurityKey::RSA_SHA256, array('type' => 'public'));
        $key->loadKey($publicKey->getCertificate());

        if ($key->verifySignature($request->getSignedRequestQuery(), $request->getSignature())) {
            return true;
        }

        return false;
    }
}
