#include <iostream>
#include <string.h>
#include <ldap.h>
#include <ldap_schema.h>


using namespace std;

#define LDAP_PORT 389

int version = LDAP_VERSION3;
LDAP *ld, *ld2;
int  return_code;
const char *ldap_host     = "ldap.forumsys.com";
const char *base_dn       = "dc=example,dc=com";
const char *admin_dn      = "cn=read-only-admin,dc=example,dc=com";
char *admin_pw            = strdup("password");
char *user_dn             = NULL;
char *user_pw             = strdup("password");
char *user_id             = strdup("uid=einstein");

char ldap_uri[255];
char *ldapErrorString = NULL;
berval credentials = { strlen(admin_pw), admin_pw }; // Admin credentials on LDAP server
berval user_cred = { strlen(user_pw), user_pw }; // Admin credentials on LDAP server
berval *returned_cred = NULL;
LDAPMessage *records=NULL, *record=NULL;    // Results from a search on LDAP server

int main() {
	// ************************
	// Set LDAP version
	ldap_set_option( ld, LDAP_OPT_PROTOCOL_VERSION, &version );

	// *************************
	// build server URI
	sprintf(ldap_uri, "ldap://%s:%d", ldap_host, LDAP_PORT);

	// ***********************************************
	// Initialize the LDAP connection
	int status = ldap_initialize(&ld, ldap_uri);
	if (status != LDAP_SUCCESS) {
		// Output the error message
		ldapErrorString = ldap_err2string(status);
		fprintf(stderr, "Connection to server failed with [%s].", ldapErrorString);
		fprintf(stderr, "LDAP server initialization error. Check [%s] server's status.", ldap_uri);
	}
	fprintf(stdout, "Successfully connected to %s\n", ldap_uri);

	// *****************************************
	// Login using the admin's credentials
	return_code = ldap_sasl_bind_s( ld, admin_dn, NULL, &credentials, NULL, NULL, &returned_cred );
	if( return_code != LDAP_SUCCESS )
	{
		// Output the error message
		fprintf(stderr, "The admin username and password were invalid: %s\n", ldap_err2string(return_code) );
		return( return_code );
	}
	ber_memfree(returned_cred);

	// *****************************************************
	// Search for the user's record on the LDAP server
	return_code = ldap_search_ext_s(ld, base_dn, LDAP_SCOPE_SUBTREE, user_id, NULL, 0, NULL, NULL, NULL, 0, &records);
	if ( return_code != LDAP_SUCCESS ) {
		// Output the error message
		fprintf(stderr, "The username is invalid: %s\n", ldap_err2string(return_code));
	}

	// ******************************************
	// Validate the user's login and password
	for ( record = ldap_first_entry( ld, records ); record != NULL; record = ldap_next_entry( ld, record ) ) {
		if ( (user_dn = ldap_get_dn( ld, record )) != NULL ) {
			fprintf(stdout, "Retrieved this record from the LDAP server: %s\n", user_dn );
			// ********************************************************************************
			// rebind using the user's distinguished name (user_dn) and password (user_cred)
			ldap_initialize(&ld2, ldap_uri);
			return_code = ldap_sasl_bind_s(ld2, user_dn, NULL, &user_cred, NULL, NULL, &returned_cred);
			if (return_code != 0) {
				// Output the error message
				fprintf(stderr, "The user's password was invalid.\n");
				return (return_code);
			} else {
				fprintf(stdout, "The user was authenticated.\n");
				ldap_unbind_ext(ld2, NULL, NULL);
			}
			ber_memfree(returned_cred);
			ldap_memfree( user_dn );
		}
	}

	free(user_pw);
	free(admin_pw);

	return (0);
}