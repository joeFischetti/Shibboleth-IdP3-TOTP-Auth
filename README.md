[![Apache License](http://img.shields.io/:license-apache-blue.svg)](http://www.apache.org/licenses/LICENSE-2.0.html)
[![Build Status](https://travis-ci.org/korteke/Shibboleth-IdP3-TOTP-Auth.svg?branch=master)](https://travis-ci.org/korteke/Shibboleth-IdP3-TOTP-Auth)

# THIS IS A DEVELEOPMENT FORK

# Shibboleth-IdP3-TOTP-Auth
> Working example of the TOTP authenticator. Work in progress! Refactoring needed! Localization needed.  

Google authenticator authentication module for Shibboleth IdP v3.  
The original version used the password flow and then called the totp flow.  The updated version (this fork) relies on the MFA flow to call the password flow first.
This authn flow will take the c14n principal name and perform the token validation based on that.  This authn flow will not work by itself.


"~~Uses External LDAP, MongoDB(EXPERIMENTAL!) or Static for seed fetching.~~"
The original implementation of this authn flow had a separate ldap configuration.  This implementation will assume the totp seed is stored in a database that the attribute resolver has the ability to pull from.
It will also assume the attribute is encrypted using a secret key (configured in a properties file).



TODO
-----
More detailed walkthrough on installation/configuration within mfa flow

Requirements
------------

Shibboleth IdP v3.4.5
Java 8

Installing
----------

* Compile souce code with maven - ```mvn clean package```
* Copy and extract totpauth-parent/totpauth-impl/target/totpauth-impl-0.5.1-bin.zip

Directory structure:
<pre>
├── conf
│   └── authn
├── edit-webapp
│   └── WEB-INF
│       └── lib
├── flows
│   └── authn
│       └── Totp
└── views
</pre>

* Copy conf --> $IDP-HOME/conf  
* Copy edit-webapp  --> $IDP-HOME/edit-webapp  
* Copy flows  --> $IDP-HOME/flows  
* Copy views  --> $IDP-HOME/views  

Modify $IDP_HOME/conf/idp.properties:

add ", /conf/totpauthn.properties" to idp.additionalProperties= so it looks like:
```idp.additionalProperties= /conf/ldap.properties, /conf/saml-nameid.properties...... , /conf/totpauthn.properties```

And change the idp.authn.flows to point to the MFA flow:
```idp.authn.flows = Password --> idp.authn.flows = MFA```


Add TOTP bean to $IDP_HOME/conf/authn/general-authn.xml, to the element:
```
 "<util:list id="shibboleth.AvailableAuthenticationFlows">"
```
  New Bean
```
        <bean id="authn/Totp" parent="shibboleth.AuthenticationFlow"
                p:passiveAuthenticationSupported="true"
                p:forcedAuthenticationSupported="true">
            <property name="supportedPrincipals">
                <util:list>
                    <bean parent="shibboleth.SAML2AuthnContextClassRef"
                        c:classRef="urn:oasis:names:tc:SAML:2.0:ac:classes:TimeSyncToken" />
                </util:list>
            </property>
        </bean>
```
And Add a bean to the MFA flow:
```
<bean parent="shibboleth.SAML2AuthnContextClassRef"
                        c:classRef="urn:oasis:names:tc:SAML:2.0:ac:classes:TimeSyncToken" />
```

And then within $IDP_HOME?conf/authn/mfa-authn-config.xml, you'll need to add a 'nextFlow= "authn/Totp"' somewhere

### Rebuild idp.war
* run $IDP-HOME/bin/build.sh
* If you need, move that war-file to containers "webapps" directory (tomcat, jetty, etc)
* Restart container

Seed Fetching
-------------
From an AttributeResolver, which is the only way that really matters:

Within $IDP_HOME/conf/attribute-resolver.xml
you'll want to create a new attribute definition that will reference the seed attribute.  The example source uses the "description" attribute.  That would look like the following:

```
        <AttributeDefinition xsi:type="Simple" id="description" sourceAttributeID="description">
                <Dependency ref="myLDAP" />
        </AttributeDefinition>

``` 

The attribute in your directory will need to match the following form:
totpseed=(.......)

The helper below will generate the encrypted value that can be stored in the directory.

Adding new seed to user
----------------------

"~~At the moment you need to add your token codes to the repository with external process. I will create some kind of registeration flow to the IdP.~~"

I have no plans to impelement a registration process within the IdP for the seed.  This can (and should?) be handled elsewhere/via some outside process.  The IdP should be used for login events, not account management.

That said, there's a helper application in EncryptionHelpers that will generate 16character strings that can be used as seeds, along with an encrypted value for insertion into the database.  The key used for encryption is hardcoded.  In addition, it will also print out a url which can be used as input for a QR code generator.

You can build the helper:
cd EncryptionHelpers
./build.sh

And run it with:
./run.sh

Afterwards, run something like the following:
qrencode -o '/path/to/png/outputfile' -s6 'otpauth://totp/Shibboleth?secret=SOMTHING'
