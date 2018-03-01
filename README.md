![](logo_s.png)

##### Thomas Schwade - February 28, 2018

## An approach to Single sign-on with Natural Ajax applications

### What do we want to achieve?

If we are running a Natural Ajax web application and need to load a page from a second Natural Ajax web application, we are normally prompted to authenticate ourselves also against the second web application, even if that application is running against the same Natural backend. 

This article proposes a technique to transfer the once entered credentials in a secure way to the second web application, so that the second login is avoided.

### Working principle 

We assume for this example that the web applications are deployed on a Tomcat server on Linux.

Web application AppA gets a customized Logon page. This Logon page has an adapter listener that encrypts the entered credentials with the public key of a previously created key pair and stores the encrypted value in the session context.

When a page PageA in application AppA needs to load a page PageB from a second application AppB, PageA gets an adapter listener that reads the encrypted credentials from the session context, creates a temporary access token with a very short life span and passes this token to the Natural program that handles PageA. This Natural program can then add the access token to the URL of PageB and load the page.

On the side of AppB a servlet filter decrypts the access token with the private key and passes the credentials to the Logon page of AppB. The Logon page accepts the credentials and loads PageB without further logon. 

### The package net.zerodrive.ssoservices

Build the package net.zerodrive.ssoservices into a .jar file and place it into the WEB-INF/lib directory of both AppA and AppB. In order to build the package you need to add servlet-api.jar from your Tomcat distribution and cis.jar from your Natural Ajax distribution to the Java build path.

### The Logon page

In application AppA create a customized Logon page as described in [Developing Customized Logon and Disconnect Pages](https://documentation.softwareag.com/naturalONE/natONE841/core/njx/njx-customlogon.htm#njx-customlogon). Add the class net.zerodrive.ssoservices.SetToken to the Logon page as adapter listener. 

### PageA in web application AppA

If PageA is a page that wants (for instance) to load a page from a second web application into a subpage, add the class net.zerodrive.ssoservices.GetToken as adapter listener to PageA. Also add an invisible data field of type string to PageA and name it "token".

	<?xml version="1.0" encoding="UTF-8"?>
	<natpage adapterlisteners="net.zerodrive.ssoservices.GetToken" natsinglebyte="true" natkcheck="true" xmlns:njx="http://www.softwareag.com/njx/njxMapConverter">
    <xcidatadef dataprop="token" datatype="xs:string">
    </xcidatadef>
	...

In the example we open the subpage in response to a button click. The adapter listener GetToken listens for an event onGetToken. So we either name the button event accordingly or modify the adapter listener to match the name of the event of our choice. 

    <button name="Open subpage" method="onGetToken">
    </button>

Look at the Natural program that handles the page:

	DEFINE DATA LOCAL
	1 SUBPAGEURL (A) DYNAMIC
	1 TOKEN (A) DYNAMIC
	END-DEFINE
	*
	PROCESS PAGE USING "NEWA"
	*
	DECIDE ON FIRST *PAGE-EVENT
  		VALUE U'nat:page.end', U'nat:browser.end'
    		IGNORE
  		VALUE U'onGetToken'
			SUBPAGEURL := "http://snowball:8480/AppB/servlet/StartCISPage?PAGEURL=/cisnatural/NatLogon.html&xciParameters.natsession=AppB"
		    COMPRESS SUBPAGEURL "&token=" TOKEN TO SUBPAGEURL LEAVING NO 
		    PROCESS PAGE UPDATE FULL
  		NONE VALUE
    		PROCESS PAGE UPDATE
	END-DECIDE
	*
	END

The adapter listener returns an authentication token for the user in the variable TOKEN. The event handler code adds the token value as parameter to the web page URL.

Based on the sample implementation, the token has a life span of just two seconds, which should be long enough to open the page, but short enough that the token cannot be reused by a potential attacker who might have read its value in a log file. The life span of the token can be changed in the class TokenFilter.java.

### The servlet filter

Now we need a way on the server side to reconstruct the user credentials from the authentication token. This is done by a servlet filter installed in web application AppB.

In WEB-INF/web.xml of AppB add the following filter declaration to activate the servlet filter.

    <filter>
        <filter-name>TokenFilter</filter-name>
        <filter-class>net.zerodrive.ssoservices.TokenFilter</filter-class>
    </filter>
	<filter-mapping> 
		<filter-name>TokenFilter</filter-name> 
	    <url-pattern>*.html</url-pattern>
	    <servlet-name>StartCISPage</servlet-name>
	</filter-mapping> 

### The encryption

For the token encryption we need a key pair and for the access to the private key a password. We store both in the Tomcat conf directory (see below for a risk consideration).

Choose a long and secure password (not exactly this one) and store it in a password file:  

	tsh@ubuntu64:/opt/tomcat/conf$ sudo echo "P^t6MheV?uKIhCJP5#GH5h%d-oajh2_a4XF40oE34A59XnJEB4kR9m-!" > keystorepass

Create a key pair in a keystore file. When prompted for a password, enter the one above:  

	tsh@ubuntu64:/opt/tomcat/conf$ keytool -genkeypair -alias mykey -keyalg RSA -keysize 3072 -keystore keystore.jks

Make the tomcat user owner of these files:

	tsh@ubuntu64:/opt/tomcat/conf$ sudo chown tomcat:tomcat keystore*

Make the sure that only the owner may read the files. Note that in a proper Tomcat installation it is not allowed to login interactively with the user tomcat.

	tsh@ubuntu64:/opt/tomcat/conf$ sudo chmod 400 keystore*

### Risk consideration

The authentication token is safe from being misused for the following reasons: It has a life span of (by default) two seconds, which is long enough to load the new page, but too short for an eavesdropper to use it a second time. And it is only accepted when the page request originates from the same IP as the server.

Storing the private key password in a file in clear text is the one potential point of attack to the solution. But by protecting the files with the correct access rights we can minimize the risk down to the point that only a malevolent administrator can break the solution. And in fact no system at all is safe from a rogue administrator.

Why at all do we store the private key password in clear text and not encrypted? There is a very instructive [article](https://t-rob.net/2011/10/24/encrypting-passwords-in-config-files-secure-or-not/) that points out in detail that encrypting a password in such a situation will most likely even lead to less security. Instead it seems preferable to use a very long random and unreadable password of for instance 63 characters and to store it in clear text in a file with strongly limited access rights.










