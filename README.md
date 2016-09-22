# Example: Password Authentication Using OpenLDAP

While working on a project, I built this simple example, using the OpenLDAP libraries to authenticate user credentials against a version 3 LDAP.  This example is based on my own retooling of code and examples found in a few different places:
* a post on [StackOverflow](http://stackoverflow.com/questions/16168293/how-to-do-password-authentication-for-a-user-using-ldap).
* Oracle's guide "[LDAP SDK for C Programming](https://docs.oracle.com/cd/E19957-01/817-6707/index.html)".
* a [publicly available LDAP server](http://www.forumsys.com/en/tutorials/integration-how-to/ldap/online-ldap-test-server) developers can test their code against.  Many thanks to [Forum Systems](https://www.facebook.com/ForumSystems)!!! The LDAP server they provided saved me at least a few hours of effort.  :smile:

With a little tweaking of this code, this project can be used as a starting point to implement an LDAP client with user authentication.
