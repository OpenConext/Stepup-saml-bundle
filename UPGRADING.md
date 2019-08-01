# UPGRADE FROM X to 4.1.9

When using this bundle with Symfony 4.3 you should configure the templating engine:

```yaml
framework:
    templating:
        engines:
            - twig
```        

# UPGRADE FROM 3.X to 4.X
This release makes error reporting more specific. This release changed the API of the
`ReceivedAuthnRequestQueryString::getSignatureAlgorithm` method, returning the signature algorithm url decoded. Any
code using this method should be updated removing the url_decode call to prevent double decoding of the sigalg value.

# UPGRADE FROM 2.X to 3.X

## SimpleSamlPHP SAML2
The most noticable change is the upgrade of the `simplesamlphp/saml2` library upgrade from version 1 to 3. This
resulted in a bundle wide upgrade of the SAML2 namespaces and the implementation of the SAML2 NameID implementaion.

### Update instruction
When upgrading the library some other dependencies are to be upgraded most notable is `robrichards/xmlseclibs`. To
streamline the upgrade the following installtion instructions are recommended:

```
composer remove surfnet/stepup-saml-bundle --ignore-platform-reqs
composer require surfnet/stepup-saml-bundle "^3.0" --ignore-platform-reqs
```

:grey_exclamation: Simply running `composer update surfnet/stepup-saml-bundle "^3.0"` will probably fail as other 
dependencies will block the update of the package.

### Code changes
After updating the SAML2 library, we advice you to scan your project for usages of the SAML2 library. You can do 
this by grepping your project for usages of the old PEAR style SAML2 classnames.

**Namespace**

Grep for usages `SAML2_` in your application. PEAR style class references should be updated to their PSR 
counterparts. Doing so is quite easy.

```
// old style
use SAML2_Assertion;

// new style
use SAML2\Assertion;
```

**NameID**

Using NameID values was changed in the SAML2 library. Instead of receiving an array representation of the NameId 
`['Value' => 'john_doe', 'Format' => 'unspecified')`, a value object is returned. Please inspect your project
for usages of the getNameId method on assertions.

**XMLSecurityKey**

Finally all usages of `XMLSecurityKey` should be checked. The `XMLSecurityKey` objects are now loaded from the
`RobRichards` namespace.

# UPGRADE FROM 1.X to 2.X

## Multiplicity

The multiplicity functionality has been removed from `Surfnet\SamlBundle\SAML2\Attribute\AttributeDefinition`.
 This means that the method `AttributeDefinition::getMultiplicity()` no longer exists. Furthermore, the related
 constants `AttributeDefinition::MULTIPLICITY_SINGLE` and `AttributeDefinition::MULTIPLICITY_MULTIPLE` have been
 removed. 
 
**WARNING** The value of an attribute is now always an array of strings, it can no longer be `null` or `string`.
 This means code relying on the values of attributes should be modified to always accept `string[]` as return value
 and handle accordingly.

The following deprecated methods have been removed:

| Class                                                | Removed method   | Replaced with         |
| ---------------------------------------------------- | ---------------- | --------------------- |
| `Surfnet\SamlBundle\SAML2\Response\AssertionAdapter` | `getAttribute()` | `getAttributeValue()` |
