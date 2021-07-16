<?php

namespace Surfnet\SamlBundle\SAML2\Extensions;

use SAML2\XML\Chunk as SAML2Chunk;

trait ExtensionsMapperTrait
{

    /**
     * @var Extensions
     */
    private $extensions;

    private function loadExtensionsFromSaml2AuthNRequest()
    {
        $this->extensions = new Extensions();
        if (!empty($this->request->getExtensions())) {
            $rawExtensions = $this->request->getExtensions();
            /** @var SAML2Chunk $rawChunk */
            foreach ($rawExtensions as $rawChunk) {
                switch ($rawChunk->localName) {
                    case 'UserAttributes':
                        $this->extensions->addChunk(
                            new GsspUserAttributesChunk($rawChunk->xml)
                        );
                        break;
                    default:
                        $this->extensions->addChunk(
                            new Chunk(
                                $rawChunk->localName,
                                $rawChunk->namespaceURI,
                                $rawChunk->xml
                            )
                        );
                }
            }
        }
    }

    public function getExtensions(): Extensions
    {
        if (!isset($this->extensions)) {
            $this->extensions = new Extensions();
        }
        return $this->extensions;
    }

    public function setExtensions(Extensions $extensions)
    {
        $this->extensions = $extensions;
        $samlExt = [];
        foreach ($this->extensions->getChunks() as $chunk) {
            $samlExt[] = new SAML2Chunk($chunk->getValue());
        }
        $this->request->setExtensions($samlExt);
    }
}
