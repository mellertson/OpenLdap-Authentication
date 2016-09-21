#include <iostream>
#include <ldap.h>
#include <ldap_cdefs.h>
#include <ldap_features.h>
#include <ldap_schema.h>
#include <ldap_utf8.h>

using namespace std;

#define LDAP_PORT 389

int version = LDAP_VERSION3;
LDAP *ld;
int  rc;
int  msgid;
int  auth_method    = LDAP_AUTH_SIMPLE;
int desired_version = LDAP_VERSION3;
char *ldap_host     = "ldap.forumsys.com";
char *admin_dn = "cn=read-only-admin,dc=example,dc=com";
char *user_dn       = "cn=read-only-admin,dc=example,dc=com";
char *user_pw       = "password";
char ldap_uri[255];
char *ldapErrorString = NULL;
berval credentials = { strlen(user_pw), user_pw }; // Admin credentials on LDAP server
berval *returned_cred = NULL;

int main() {
	// Set LDAP version
	ldap_set_option( ld, LDAP_OPT_PROTOCOL_VERSION, &version );

	// build server URI
	sprintf(ldap_uri, "ldap://%s:%d", ldap_host, LDAP_PORT);

	// ***********************************************
	// Initialize the LDAP connection
	int status = ldap_initialize(&ld, ldap_uri);
	if (status != LDAP_SUCCESS) {
		/* int errno_save = errno; */
		perror("ldap_initialize() failed"); /* This call shows the error message related to errno. */

		ldapErrorString = ldap_err2string(status);
		printf("Connection to server failed with [%s].", ldapErrorString);
		printf("LDAP server initialization error. Check [%s] server's status.", ldap_uri);
	}

	printf("Successfully connected to %s", ldap_uri);

	// ********************************
	// Search for the user's record
	rc = ldap_sasl_bind_s( ld, user_dn, NULL, &credentials, NULL, NULL, &returned_cred );
	if( rc != LDAP_SUCCESS )
	{
		fprintf(stderr, "ldap_sasl_bind returned: %s\n", ldap_err2string(rc) );
		return( 1 );
	}

	return 0;
}