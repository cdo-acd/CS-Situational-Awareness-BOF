#include <windows.h>
#include "bofdefs.h"
#include "base.c"
#include <stdbool.h>

#ifdef BOF
void make_token(char * domain, char * username, char * password) {
	internal_printf("Domain: %s\nUsername: %s\nPassword: %s\n", domain, username, password);

	HANDLE hToken;


	// LOGON32_LOGON_NEW_CREDENTIALS = 9
	// LOGON32_PROVIDER_DEFAULT = 0
	bool success = ADVAPI32$LogonUserA(username, domain, password, 9, 0, &hToken);

	internal_printf("\nMake Token Success: %d\nToken: %p\n", success, hToken);

	if (success == 1) {
		success = ADVAPI32$ImpersonateLoggedOnUser(hToken);
		internal_printf("\nImpersonate Success: %d\n", success);
	}
}

VOID go(
	IN PCHAR Buffer,
	IN ULONG Length
)
{
	datap parser = {0};
	BeaconDataParse(&parser, Buffer, Length);
	char * domain = BeaconDataExtract(&parser, NULL);
	char * username = BeaconDataExtract(&parser, NULL);
	char * password = BeaconDataExtract(&parser, NULL);

	if(!bofstart())
	{
		return;
	}

	make_token(domain, username, password);

	printoutput(TRUE);
};

#else

int main()
{
//code for standalone exe for scanbuild / leak checks
}

#endif
