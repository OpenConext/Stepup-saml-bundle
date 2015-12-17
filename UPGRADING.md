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
