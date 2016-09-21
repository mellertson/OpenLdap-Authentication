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
		perror("ldap_initialize() failed");
		ldapErrorString = ldap_err2string(status);
		printf("Connection to server failed with [%s].", ldapErrorString);
		printf("LDAP server initialization error. Check [%s] server's status.", ldap_uri);
	}
	printf("Successfully connected to %s\n", ldap_uri);

	// *****************************************
	// Login using the admin's credentials
	return_code = ldap_sasl_bind_s( ld, admin_dn, NULL, &credentials, NULL, NULL, &returned_cred );
	if( return_code != LDAP_SUCCESS )
	{
		fprintf(stderr, "ldap_sasl_bind returned: %s\n", ldap_err2string(return_code) );
		return( return_code );
	}
	ber_memfree(returned_cred);

	// *****************************************************
	// Search for the user's record on the LDAP server
	return_code = ldap_search_ext_s(ld, base_dn, LDAP_SCOPE_SUBTREE, "uid=einstein", NULL, 0, NULL, NULL, NULL, 0, &records);
	if ( return_code != LDAP_SUCCESS ) {
		fprintf(stderr, "ldap_search_ext_s: %s\n", ldap_err2string(return_code));
	}

	// *************************************
	// Validate the user's password
	for ( record = ldap_first_entry( ld, records ); record != NULL; record = ldap_next_entry( ld, record ) ) {
		if ( (user_dn = ldap_get_dn( ld, record )) != NULL ) {
			printf( "Retrieved this record from the LDAP server: %s\n", user_dn );
			/* rebind */
			ldap_initialize(&ld2, ldap_uri);
			return_code = ldap_sasl_bind_s(ld2, user_dn, NULL, &user_cred, NULL, NULL, &returned_cred);
			printf("Return code from LDAP server after ldap_sasl_bind_s(): %d\n", return_code);
			if (return_code != 0) {
				printf("The user credentials couldn't be authenticated.\n");
				return (return_code);
			} else {
				printf("The user was authenticated.\n");
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