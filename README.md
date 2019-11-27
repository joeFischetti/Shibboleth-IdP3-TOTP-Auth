[![Apache License](http://img.shields.io/:license-apache-blue.svg)](http://www.apache.org/licenses/LICENSE-2.0.html)
[![Build Status](https://travis-ci.org/korteke/Shibboleth-IdP3-TOTP-Auth.svg?branch=master)](https://travis-ci.org/korteke/Shibboleth-IdP3-TOTP-Auth)

# Shibboleth-IdP3-TOTP-Auth
##This is a developement fork


## Why use this plugin?
MFA, or multi factor authentication, is used to provide additional security on top of standard password based authentication.  
The [obvious] problem with password-only authentication is that when a password for an account is compromised, that account is compromised.  
MFA introduces additional factors on top of the password (something you know), typically in the form of "something you have" or "something you are".

This plugin implements MFA using "something you have", or more specifically, a time based one time password (totp).

The major downside with some of the other impelementations for MFA (such as Duo), is the reliance on an outside service for authentication.
In addition to spreading out the management footprint and introducing this dependency
- Duo supports push notifications which are a known attack attack vector.
- TOTP keys are "pulled".  i.e. the user needs to look at it and provide it.  There's no chance they'll passively click a notification.

That said, no MFA is perfect and it can be a pain in the ass for the users.

## What does this plugin do?
This plugin hooks into the built in MFA flows within the Shibboleth IDP to provide support for a totp.  
It's was developed as a fork to the original plugin by [].  
Details are below, but in short, that plugin didn't work with current versions of the idp for a number of reasons:
- There was no way to hook it into the MFA login flow
- It managed/called the password flow interally
- No principal name derived from IDP internal mechanisms
- Tried to implement token registration
- Made external connections to the token databases on it's own (instead of relying on internal IdP mechanisms)


## How does this plugin work?
A high level overview of how the plugin works is below.
- Using the built-in MFA flow, call this plugin as the 'nextFlow'
- Get the user's principle name for the session
- Using the attribute resolver, look up the attribute that contains the encrypted seed value
- Decrypt the seed value.
- Prompt the user for the one time passcode (displayed in their google authenticator, or similar, app)
- Canonicalize the OTP, and pass it along with the decrypted seed to the google authenticator API
- Return pass/fail



## More technical details
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
* Copy and extract totpauth-parent/totpauth-impl/target/totpauth-impl-1.0-bin.zip

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
* Make sure you've removed any old versions of the totpauth-impl or totpauth-api libraries in $IDP-HOME/bin/build.sh
** Only necessary if you've deployed versions other than the current
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
