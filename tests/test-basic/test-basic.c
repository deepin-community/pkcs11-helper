#include <stdio.h>
#include <stdlib.h>
#include "../../config.h"
#include <pkcs11-helper-1.0/pkcs11h-core.h>

static
void
fatal (const char * const m, CK_RV rv) {
	fprintf (stderr, "%s - %08lu - %s\n", m, rv, pkcs11h_getMessage (rv));
	exit (1);
}

static
void
_pkcs11h_hooks_log (
	IN void * const global_data,
	IN unsigned flags,
	IN const char * const format,
	IN va_list args
) {
	vfprintf (stdout, format, args);
	fprintf (stdout, "\n");
	fflush (stdout);
}

int main () {
	CK_RV rv;

	printf ("Version: %08x\n", pkcs11h_getVersion ());
	printf ("Features: %08x\n", pkcs11h_getFeatures ());

	printf ("Initializing pkcs11-helper\n");

	if ((rv = pkcs11h_initialize ()) != CKR_OK) {
		fatal ("pkcs11h_initialize failed", rv);
	}

	printf ("Registering pkcs11-helper hooks\n");

	if ((rv = pkcs11h_setLogHook (_pkcs11h_hooks_log, NULL)) != CKR_OK) {
		fatal ("pkcs11h_setLogHook failed", rv);
	}

	pkcs11h_setLogLevel (TEST_LOG_LEVEL);

	printf ("Adding provider '%s'\n", TEST_PROVIDER);

	if (
		(rv = pkcs11h_addProvider (
			"reference1",
			TEST_PROVIDER,
			TRUE,
			PKCS11H_PRIVATEMODE_MASK_DECRYPT,
			PKCS11H_SLOTEVENT_METHOD_POLL,
			0x55,
			TRUE
		)) != CKR_OK
	) {
		fatal ("pkcs11h_addProvider failed", rv);
	}

	printf ("Terminating pkcs11-helper\n");

	if ((rv = pkcs11h_terminate ()) != CKR_OK) {
		fatal ("pkcs11h_terminate failed", rv);
	}

	exit (0);
	return 0;
}
