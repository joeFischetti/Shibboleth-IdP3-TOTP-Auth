[![Apache License](http://img.shields.io/:license-apache-blue.svg)](http://www.apache.org/licenses/LICENSE-2.0.html)
[![Build Status](https://travis-ci.org/korteke/Shibboleth-IdP3-TOTP-Auth.svg?branch=master)](https://travis-ci.org/korteke/Shibboleth-IdP3-TOTP-Auth)

# Shibboleth-IdP3-TOTP-Auth
Google authenticator authentication module for Shibboleth IdP v3. 

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


## How do I implement the plugin?
The steps to use the plugin are as follows:
- Download the source
- run 'mvn clean package' to build it
- unzip the built package and move the files to your $IDP-HOME directory
- Set up your mfa-flow to call this (using some predefined criteria)
- Test test test

## More technical details
The original version of this plugin used the password flow and then called the totp flow.  The updated version (this fork) relies on the MFA flow to call the password flow first.
This authn flow will take the c14n principal name and perform the token validation based on that.  This authn flow will not work by itself.


The original implementation of this authn flow had a separate ldap configuration.  This implementation will assume the totp seed is stored in a database that the attribute resolver has the ability to pull from.
It will also assume the attribute is encrypted using a secret key, encryption algorithm, mode, and padding (configured in a properties file, defaulted to blowfish/ecb/pkcs5padding). The attribute should be in the form of "totpseed=(iv:ENCRYPTED VALUE)" with, optionally, other tags before or after the seed.  Note for encryption modes that don't require the iv, it's possible to omit the iv in the seed.  The other tags will be ignored by this plugin and whould be used for outside tooling.  An example ldif is below.  In this case there's an additional tag called "friendlyName" which is used for identifying the seed (when there's more than one) for the end user.  

```
# extended LDIF
#
# LDAPv3
# base <o=base> (default) with scope subtree
# filter: description=totp*
# requesting: description
#

# 1234567, base
dn: uniqueidentifier=1234567,o=base
description: Some existing description value that may or may not take up more
 than one line
description: totpseed=(ANENCRYPTEDSEEDVALUETHATWILLBEUSEDBYTHEIDP)friendlyNa
  me=(AndroidPhone)

# 1234568, base
dn: uniqueidentifier=1234568,o=base
description: Some existing description
description: totpseed=(ANENCRYPTEDSEEDVALUETHATWILLBEUSEDBYTHEIDP)friendlyNa
  me=(Google Authenticator)

# search result
search: 2
result: 0 Success

# numResponses: 3
# numEntries: 2
```

There's a helper application that can handle the creation of these keys in [EncryptionHelpers].  Details are below

TODO
-----
- More detailed walkthrough on installation/configuration within mfa flow
- Troubleshoot/identify issues while running with oracle java instead of openjdk
	It's related to the key sizes used in oracle java... the key's i've used require the "unlimited strength" policy
	Details can be found [https://www.andreafortuna.org/2016/06/08/java-tips-how-to-fix-the-invalidkeyexception-illegal-key-size-or-default-parameters-runtime/]


Requirements
------------

- Shibboleth IdP v3.4.5
- Java 8
- Slightly more than a basic understanding of identity management
- Some way to insert encrypted seeds into a directory.
  - Currently, the plugin only supports seeds encrypted with ebc algorithms (there's no support for an IV).


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
```
idp.additionalProperties= /conf/ldap.properties, /conf/saml-nameid.properties...... , /conf/totpauthn.properties
```


And change the idp.authn.flows to point to the MFA flow:
```
idp.authn.flows = Password --> idp.authn.flows = MFA
```


Add TOTP bean to $IDP_HOME/conf/authn/general-authn.xml, to the element:
```
 "<util:list id="shibboleth.AvailableAuthenticationFlows">"
```
  New Bean
```
        <bean id="authn/Totp" parent="shibboleth.AuthenticationFlow"
                p:passiveAuthenticationSupported="true"
		p:nonBrowserSupported="false"
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

An example of an mfa-authn-config.xml that would call the authn/Totp based on membership in a particular goup in ldap is below.
You should modify the script as necessary.
```
    <util:map id="shibboleth.authn.MFA.TransitionMap">
        <!-- First rule runs the Password login flow. -->
        <entry key="">
            <bean parent="shibboleth.authn.MFA.Transition" p:nextFlow="authn/Password" />
        </entry>

        <!--
        Second rule runs a function if Password succeeds, to determine whether an additional
        factor is required.
        -->
        <entry key="authn/Password">
            <bean parent="shibboleth.authn.MFA.Transition" p:nextFlowStrategy-ref="checkSecondFactor" />
        </entry>

        <!-- An implicit final rule will return whatever the final flow returns. -->
    </util:map>




    <bean id="checkSecondFactor" parent="shibboleth.ContextFunctions.Scripted" factory-method="inlineScript"
        p:customObject-ref="shibboleth.AttributeResolverService">
        <constructor-arg>
            <value>


<![CDATA[
        //Set up the logger
        logger = Java.type("org.slf4j.LoggerFactory").getLogger("net.shibboleth.idp.checkSecondFactor");

        nextFlow = null;

        // Go straight to second factor if we have to, or set up for an attribute lookup first.
        authCtx = input.getSubcontext("net.shibboleth.idp.authn.context.AuthenticationContext");
        mfaCtx = authCtx.getSubcontext("net.shibboleth.idp.authn.context.MultiFactorAuthenticationContext");

	//Note here, profileContext.isBrowserProfile() is necessary for supporting (by bypassing totp) non browser login flows, i.e. ECP
        if (mfaCtx.isAcceptable() && profileContext.isBrowserProfile()) {

                // Attribute check is required to decide if first factor alone is enough.
                resCtx = input.getSubcontext("net.shibboleth.idp.attribute.resolver.context.AttributeResolutionContext", true);

                // Look up the username using a standard function.
                usernameLookupStrategyClass = Java.type("net.shibboleth.idp.session.context.navigate.CanonicalUsernameLookupStrategy");
                usernameLookupStrategy = new usernameLookupStrategyClass();
                resCtx.setPrincipal(usernameLookupStrategy.apply(input));


		//Look up the "memberOf" attribute, and the "description" attribute
		//  You'll remember that 'description' stores our totpseed.  We wouldn't
		//  want to try totp if there were no seed stored
                resCtx.getRequestedIdPAttributeNames().add("ibm-allgroups");
                resCtx.getRequestedIdPAttributeNames().add("description");
                resCtx.resolveAttributes(custom);


                // Check for an attribute that authorizes use of this factor.
                groupAttr = resCtx.getResolvedIdPAttributes().get("ibm-allgroups");
                seedAttr = resCtx.getResolvedIdPAttributes().get("description");

                valueType =  Java.type("net.shibboleth.idp.attribute.StringAttributeValue");

                //Check if either attribute is null, and if the groupAttr contains the group we expect it to
                if (groupAttr != null
                        && seedAttr != null
                        && groupAttr.getValues().contains(new valueType("cn=mfarequired,ou=groups,o=marist"))
                        //&& seedAttr.getValues().contains(new valueType("     "))
                        ) {
                        nextFlow = "authn/Totp";

                        for(i = 0; i < groupAttr.getValues().size(); i++){
                                logger.debug("user group membership:  {}", groupAttr.getValues().get(i));
                        }
                }

                input.removeSubcontext(resCtx);   // cleanup

        }

        nextFlow;   // pass control to second factor or end with the first

]]>


            </value>
        </constructor-arg>
    </bean>

```

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
It's also possible to store the encrypted value with an iv (for other encryption modes that need such things)
In that case your seed would be:
totpseed=(iv:encryptedseed)

The helper below will generate the encrypted value that can be stored in the directory.

Adding new seed to user
----------------------

I have no plans to impelement a registration process within the IdP for the seed.  This can (and should?) be handled elsewhere/via some outside process.  The IdP should be used for login events, not account management.

That said, there's a helper application in EncryptionHelpers that will generate 16character strings that can be used as seeds, along with an encrypted value for insertion into the database.  The key used for encryption is hardcoded.  In addition, it will also print out a url which can be used as input for a QR code generator.

You can build the helper:
```
cd EncryptionHelpers
./build.sh
```

And run it with:
```
./run.sh
```

Afterwards, run something like the following:
```qrencode -o '/path/to/png/outputfile' -s6 'otpauth://totp/Shibboleth?secret=SOMTHING'```
