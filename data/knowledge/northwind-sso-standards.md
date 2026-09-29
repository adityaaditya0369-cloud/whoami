# Northwind SSO standards (SAMPLE - fictional company)

This is sample content for the demo knowledge base. Replace it with the customer's own runbooks and vendor guides.

## Signing
All new SAML connections sign the assertion with RSA-SHA256. SHA-1 signing is not allowed after 2026. If a vendor only accepts SHA-1, raise a security exception before cutover and record it in the decisions register.

## NameID
The standard NameID is the user's email address (mail attribute) with the emailAddress format. Applications that used the Okta user id as NameID need an account re-link agreed with the vendor; the directory does not hold Okta ids.

## Group access
Access to every application is controlled by a directory group named PF-<application>-Users. Okta-only groups must be recreated in Active Directory and populated before the pilot, because PingFederate reads group membership from the directory only (memberOf). Assignments to the Everyone group are not allowed for applications with personal data.

## Group attributes
Group attributes sent to applications are built with an LDAP search on memberOf. Regular-expression group filters from Okta must be rewritten as prefix (starts with) filters; test the resulting group list for a test user before cutover.

## Attribute sources
Attributes must come straight from the directory. OGNL expressions are only allowed with a security exception. Values that Okta computed (for example upper-case department codes) are pre-computed into extensionAttribute1-15 by the directory team.

## Pilot and waves
Pilot applications must have a test or sandbox instance and must not be business critical. Business-critical applications go in the last wave with a change window agreed with the business owner.

## Cutover and rollback
Keep the Okta application active until the PingFederate connection is verified in production. Rollback means switching the SP back to the Okta issuer, SSO URL and signing certificate captured before cutover. The rollback window is 7 days; after that the Okta application is deactivated.

## Certificates
The Okta signing certificate must be valid for the whole rollback window. If it expires within 60 days of the cutover, rotate it on Okta first.

## Expense Portal (vendor notes)
The Expense Portal vendor supports SP-initiated and IdP-initiated SSO. The vendor accepts SHA-256. The role attribute must be one of Employee, Approver or Admin; any other value locks the user out.
