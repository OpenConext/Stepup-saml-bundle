# SURFnet SamlBundle

<!--
       [![Build Status](https://travis-ci.org/SURFnet/Stepup-bundle.svg)](https://travis-ci.org/SURFnet/Stepup-bundle) [![Scrutinizer Code Quality](https://scrutinizer-ci.com/g/SURFnet/Stepup-bundle/badges/quality-score.png?b=develop)](https://scrutinizer-ci.com/g/SURFnet/Stepup-bundle/?branch=develop) [![SensioLabs Insight](https://insight.sensiolabs.com/projects/5b8b8d8b-e917-4954-818b-782d9e181c75/mini.png)](https://insight.sensiolabs.com/projects/5b8b8d8b-e917-4954-818b-782d9e181c75)
-->

A bundle that adds SAML capabilities to your application using [simplesamlphp/saml2][1]

Developed as part of the [SURFnet StepUp Gateway][2]

# Step-up Bundle
[![Build Status](https://travis-ci.org/SURFnet/Stepup-bundle.svg)](https://travis-ci.org/SURFnet/Stepup-bundle) [![Scrutinizer Code Quality](https://scrutinizer-ci.com/g/SURFnet/Stepup-bundle/badges/quality-score.png?b=develop)](https://scrutinizer-ci.com/g/SURFnet/Stepup-bundle/?branch=develop) [![SensioLabs Insight](https://insight.sensiolabs.com/projects/5b8b8d8b-e917-4954-818b-782d9e181c75/mini.png)](https://insight.sensiolabs.com/projects/5b8b8d8b-e917-4954-818b-782d9e181c75)

A Symfony2 bundle that holds shared code and framework integration for all Step-up applications.

## Installation

* Add the package to your Composer file
  ```sh
  composer require surfnet/stepup-saml-bundle
  ```

* Add the bundle to your kernel in `app/AppKernel.php`
  ```php
  public function registerBundles()
  {
      // ...
      $bundles[] = new Surfnet\StepupBundle\SurfnetSamlBundle;
  }
  ```

## Configuration

## Example Usage

### Metadata Publishing

```php
<?php

namespace Acme\SamlBundle

use Surfnet\SamlBundle\Http\XMLResponse;
use Symfony\Bundle\FrameworkBundle\Controller\Controller;
use Symfony\Component\HttpFoundation\Request;

class MetadataController extends Controller
{
    public function metadataAction(Request $request)
    {
        /** @var \Surfnet\SamlBundle\Metadata\MetadataFactory $metadataFactory */
        $metadataFactory = $this->get('surfnet_saml.metadata_factory');

        return new XMLResponse($metadataFactory->generate());
    }
}
```

### Service Provider

### Identity Provider


[1]: https://github.com/simplesamlphp/saml2
[2]: https://github.com/SURFnet/Stepup-Gateway
