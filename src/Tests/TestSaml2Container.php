<?php

namespace Surfnet\SamlBundle\Tests;

use SAML2_Compat_AbstractContainer;
use Psr\Log\LoggerInterface;

class TestSaml2Container extends SAML2_Compat_AbstractContainer
{
    /**
     * @var \Psr\Log\LoggerInterface
     */
    private $logger;

    public function __construct(LoggerInterface $logger = null)
    {
        $this->logger = $logger;
    }

    /**
     * @return LoggerInterface
     */
    public function getLogger()
    {
        return $this->logger;
    }

    /**
     * Generate a random identifier for identifying SAML2 documents.
     */
    public function generateId()
    {
        return 1;
    }

    public function debugMessage($message, $type)
    {
        $this->logger->debug($message, ['type' => $type]);
    }

    public function redirect($url, $data = array())
    {
        throw new \BadMethodCallException(sprintf(
            "[TEST] %s:%s may not be called in the Surfnet\\SamlBundle as it doesn't work with Symfony2",
            __CLASS__,
            __METHOD__
        ));
    }

    public function postRedirect($url, $data = array())
    {
        throw new \BadMethodCallException(sprintf(
            "[TEST] %s:%s may not be called in the Surfnet\\SamlBundle as it doesn't work with Symfony2",
            __CLASS__,
            __METHOD__
        ));
    }
}
