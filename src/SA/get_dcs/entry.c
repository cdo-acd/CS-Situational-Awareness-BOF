#include <windows.h>
#include "beacon.h"
#include "bofdefs.h"
#include <windns.h>
#include "base.c"

#include <winsock2.h>
#include <dsgetdc.h>
#include <lm.h>

#include "Domaininfo.h"

WINBASEAPI void* WINAPI MSVCRT$malloc(SIZE_T);

typedef PCWSTR (*myInetNtopW)(
  INT        Family,
  const VOID *pAddr,
  PWSTR      pStringBuf,
  size_t     StringBufSize
);


void query_domain(const char * domainname, unsigned short wType, const char * dnsserver)
{
    PDNS_RECORD pdns = NULL, base = NULL;
    DWORD options = DNS_QUERY_WIRE_ONLY; 
    DWORD status = 0;
    struct in_addr inaddr = {0};
    PIP4_ARRAY pSrvList = NULL;
    unsigned int i = 0;
    LPSTR errormsg = NULL;
    DNS_FREE_TYPE freetype;
    HMODULE WS = LoadLibraryA("WS2_32");
    myInetNtopW inetntow;
    int (*intinet_pton)(INT, LPCSTR, PVOID);
    if(WS == NULL)
    {
        BeaconPrintf(CALLBACK_ERROR, "Unable to load ws2 lib");
        return;
    }
    else
    {
        inetntow = (myInetNtopW)GetProcAddress(WS, "InetNtopW");
        intinet_pton = (int (*)(INT,LPCSTR,PVOID))GetProcAddress(WS, "inet_pton");
        if(!inetntow || !intinet_pton)
        {
            BeaconPrintf(CALLBACK_ERROR, "Could not load functions");
            goto END;
        }
    }
    
    freetype = DnsFreeRecordListDeep; //since when was a define not good enough for microsoft
    if(dnsserver != NULL) // I am assuming dnsserver is never set with cacheOnly
    {
        pSrvList = (PIP4_ARRAY)KERNEL32$LocalAlloc(LPTR, sizeof(IP4_ARRAY));
        if (!pSrvList)
        {
            BeaconPrintf(CALLBACK_ERROR, "could not allocate memory");      
            goto END;
        }
        if(intinet_pton(AF_INET, dnsserver, &(pSrvList->AddrArray[0])) != 1)
        {
            BeaconPrintf(CALLBACK_ERROR, "Could not convert dnsserver from ip to binary");
            KERNEL32$LocalFree(pSrvList);
            goto END;
        }
    //   pSrvList->AddrArray[0] = WSOCK32$inet_addr(dnsserver); //DNS (ASCII) to  IP address
    //   pSrvList->
        pSrvList->AddrCount = 1; 
        options = DNS_QUERY_WIRE_ONLY;
    }
    status = DNSAPI$DnsQuery_A(domainname, wType, options, pSrvList, &base, NULL);
    if(pSrvList != NULL)
        KERNEL32$LocalFree(pSrvList);
    pdns = base;
    if(status != 0 || pdns == NULL)
    {
		internal_printf("Query for domain name failed\n");
		status = KERNEL32$FormatMessageA(
			FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
			NULL,
			status,
			0,
			(LPSTR)&errormsg,
			0,
			NULL
		);
		if(status ==0)
			internal_printf("unable to convert error message\n");
		else
		{
			internal_printf("%s", errormsg);
			KERNEL32$LocalFree(errormsg);
		}
        goto END;
    }

    //this logic was modified from https://www.codeproject.com/Articles/21246/DNS-Query-MFC-based-Application DnsView.cpp
    do {

            if(pdns->wType == DNS_TYPE_A)
            {
                DWORD test = pdns->Data.A.IpAddress;
                internal_printf("%s %lu.%lu.%lu.%lu\n", pdns->pName, test & 0x000000ff, (test & 0x0000ff00) >> 8, (test & 0x00ff0000) >> 16, (test & 0xff000000) >> 24);
				internal_printf("%lu.%lu.%lu.%lu %s\n\n", test & 0x000000ff, (test & 0x0000ff00) >> 8, (test & 0x00ff0000) >> 16, (test & 0xff000000) >> 24, pdns->pName);
            }else if(pdns->wType == DNS_TYPE_NS){
                    internal_printf("NS %s %s\n", pdns->pName, pdns->Data.NS.pNameHost);
            }else if(pdns->wType == DNS_TYPE_MD){
                    internal_printf("MD %s %s\n", pdns->pName, pdns->Data.MD.pNameHost);
            }else if(pdns->wType == DNS_TYPE_MF){

                    internal_printf("MF %s %s\n", pdns->pName, pdns->Data.MF.pNameHost);
            }else if(pdns->wType == DNS_TYPE_CNAME){
                    internal_printf("CNAME %s %s\n", pdns->pName, pdns->Data.CNAME.pNameHost);
            }else if(pdns->wType == DNS_TYPE_SOA){

                    internal_printf("SOA %s  nameserv: %s\r\n", pdns->pName, pdns->Data.SOA.pNamePrimaryServer);
                    internal_printf("     admin: %s\r\n", pdns->Data.SOA.pNameAdministrator);
                    internal_printf("    serial: %lu\r\n", pdns->Data.SOA.dwSerialNo);
                    internal_printf("   refresh: %lu\r\n", pdns->Data.SOA.dwRefresh);
                    internal_printf("       ttl: %lu\r\n", pdns->Data.SOA.dwDefaultTtl);
                    internal_printf("    expire: %lu\r\n", pdns->Data.SOA.dwExpire);
                    internal_printf("     retry: %lu", pdns->Data.SOA.dwRetry);
            }else if(pdns->wType == DNS_TYPE_MB){
                    internal_printf("MB %s %s\n", pdns->pName, pdns->Data.MB.pNameHost);
            }else if(pdns->wType == DNS_TYPE_MG){
                    internal_printf("MG %s %s\n", pdns->pName, pdns->Data.MG.pNameHost);
            }else if(pdns->wType == DNS_TYPE_MR){

                    internal_printf("MR %s %s\n", pdns->pName, pdns->Data.MR.pNameHost);
            }else if(pdns->wType == DNS_TYPE_WKS){

                    inaddr.S_un.S_addr = pdns->Data.WKS.IpAddress;
                    //internal_printf("WKS %s [%s] proto: %d mask: %d\n", pdns->pName, WS2_32$inet_ntoa(inaddr), pdns->Data.WKS.chProtocol, pdns->Data.WKS.BitMask);
            }else if(pdns->wType == DNS_TYPE_PTR){

                    internal_printf("PTR %s %s\n", pdns->pName, pdns->Data.PTR.pNameHost);
            }else if(pdns->wType == DNS_TYPE_HINFO){

                    internal_printf("HINFO %s\n", pdns->pName);
                    for (i = 0; i < pdns->Data.HINFO.dwStringCount; i++) {
                            internal_printf("%s\n", pdns->Data.HINFO.pStringArray[i]);
                    }
            }else if(pdns->wType == DNS_TYPE_MINFO){
                    internal_printf("MINFO %s err: %s name: %s\n", pdns->pName, pdns->Data.MINFO.pNameErrorsMailbox, pdns->Data.MINFO.pNameMailbox);
            }else if(pdns->wType == DNS_TYPE_MX){

                    internal_printf("MX %s %s pref: %d\n", pdns->pName, pdns->Data.MX.pNameExchange, pdns->Data.MX.wPreference);
            }else if(pdns->wType == DNS_TYPE_TEXT){

                    internal_printf("TEXT %s\n", pdns->pName);
                    for (i = 0; i < pdns->Data.TXT.dwStringCount; i++) {
                            internal_printf("%s\n", pdns->Data.TXT.pStringArray[i]);
                    }
            }else if(pdns->wType ==DNS_TYPE_RP){

                    internal_printf("RP %s err: %s name: %s\n", pdns->pName, pdns->Data.RP.pNameErrorsMailbox, pdns->Data.RP.pNameMailbox);
            }else if(pdns->wType == DNS_TYPE_AFSDB){

                    internal_printf("AFSDB %s %s pref: %d\n", pdns->pName, pdns->Data.AFSDB.pNameExchange, pdns->Data.AFSDB.wPreference);
            }else if(pdns->wType == DNS_TYPE_X25){

                    internal_printf("X25 %s\n", pdns->pName);
                    for (i = 0; i < pdns->Data.X25.dwStringCount; i++) {
                            internal_printf("%s\n", pdns->Data.X25.pStringArray[i]);
                    }
            }else if(pdns->wType == DNS_TYPE_ISDN){

                    internal_printf("ISDN %s\n", pdns->pName);
                    for (i = 0; i < pdns->Data.ISDN.dwStringCount; i++) {
                            internal_printf("%s\n", pdns->Data.ISDN.pStringArray[i]);
                    }
            }else if(pdns->wType == DNS_TYPE_RT){

                    internal_printf("RT %s %s pref: %d\n", pdns->pName, pdns->Data.RT.pNameExchange, pdns->Data.RT.wPreference);
            }else if(pdns->wType == DNS_TYPE_AAAA){

                    internal_printf("AAAA %s [", pdns->pName);
                    for (i = 0; i < 16; i++) {
                            internal_printf("%d", pdns->Data.AAAA.Ip6Address.IP6Byte[i]);
                            if (i != 15)
                                    internal_printf(".");
                    }
                    internal_printf("]");
            }else if(pdns->wType == DNS_TYPE_SRV){

                    internal_printf("SRV %s %s port:%d prior:%d weight:%d\n", pdns->pName, pdns->Data.SRV.pNameTarget, pdns->Data.SRV.wPort, pdns->Data.SRV.wPriority, pdns->Data.SRV.wWeight);
            }else if(pdns->wType == DNS_TYPE_WINSR){

                    internal_printf("NBSTAT %s %s\n", pdns->pName, pdns->Data.WINSR.pNameResultDomain);
            }else if(pdns->wType == DNS_TYPE_KEY){

                    internal_printf("DNSKEY %s: flags %d, Protocol %d, Algorithm %d\n", pdns->pName, pdns->Data.KEY.wFlags, pdns->Data.KEY.chProtocol, pdns->Data.KEY.chAlgorithm);
            }else{

                    internal_printf("type unhandled\n");
            }    

        pdns = pdns->pNext;
    } while (pdns);
    END:
    if(base)
    {DNSAPI$DnsFree(base, freetype);}
    FreeLibrary(WS);

}

// #ifdef BOF
// VOID go( 
// 	IN PCHAR Buffer, 
// 	IN ULONG Length 
// ) 
// {
// 	datap parser;
// 	char * target = NULL;
// 	char * server = NULL;
// 	unsigned short type = 0;

// 	if(!bofstart())
// 	{
// 		return;
// 	}
// 	BeaconDataParse(&parser, Buffer, Length);
// 	target = BeaconDataExtract(&parser, NULL);
// 	server = BeaconDataExtract(&parser, NULL);
// 	type = BeaconDataShort(&parser);
// 	server = *server == 0 ? NULL : server;
// 	query_domain(target, type, server);
// 	printoutput(TRUE);
// }
// #else
// int main(int argc, char ** argv)
// {
//         char * target = argv[1];
//         char * server = argv[2];
//         server = strlen(server) == 0 ? NULL : server;
//         unsigned short type = (unsigned short)atoi(argv[3]);
//         query_domain(target, type,server);
//         return 0;
// }
// #endif

// INT iGarbage = 1;
// LPSTREAM lpStream = (LPSTREAM)1;

// HRESULT BeaconPrintToStreamW(_In_z_ LPCWSTR lpwFormat, ...) {
// 	HRESULT hr = S_OK;
// 	va_list argList;
// 	WCHAR chBuffer[1024];
// 	DWORD dwWritten = 0;

// 	if (lpStream <= (LPSTREAM)1) {
// 		hr = OLE32$CreateStreamOnHGlobal(NULL, TRUE, &lpStream);
// 		if (FAILED(hr)) {
// 			return hr;
// 		}
// 	}

// 	va_start(argList, lpwFormat);
// 	MSVCRT$memset(chBuffer, 0, sizeof(chBuffer));
// 	if (!MSVCRT$_vsnwprintf_s(chBuffer, _countof(chBuffer), _TRUNCATE, lpwFormat, argList)) {
// 		hr = E_FAIL;
// 		goto CleanUp;
// 	}

// 	if (FAILED(hr = lpStream->lpVtbl->Write(lpStream, chBuffer, (ULONG)MSVCRT$wcslen(chBuffer) * sizeof(WCHAR), &dwWritten))) {
// 		goto CleanUp;
// 	}

// CleanUp:

// 	va_end(argList);
// 	return hr;
// }

// VOID BeaconOutputStreamW() {
// 	STATSTG ssStreamData = { 0 };
// 	SIZE_T cbSize = 0;
// 	ULONG cbRead = 0;
// 	LARGE_INTEGER pos;
// 	LPWSTR lpwOutput = NULL;

// 	if (FAILED(lpStream->lpVtbl->Stat(lpStream, &ssStreamData, STATFLAG_NONAME))) {
// 		return;
// 	}

// 	cbSize = ssStreamData.cbSize.LowPart;
// 	lpwOutput = KERNEL32$HeapAlloc(KERNEL32$GetProcessHeap(), HEAP_ZERO_MEMORY, cbSize + 1);
// 	if (lpwOutput != NULL) {
// 		pos.QuadPart = 0;
// 		if (FAILED(lpStream->lpVtbl->Seek(lpStream, pos, STREAM_SEEK_SET, NULL))) {
// 			goto CleanUp;
// 		}

// 		if (FAILED(lpStream->lpVtbl->Read(lpStream, lpwOutput, (ULONG)cbSize, &cbRead))) {		
// 			goto CleanUp;
// 		}

// 		BeaconPrintf(CALLBACK_OUTPUT, "%ls", lpwOutput);
// 	}

// CleanUp:

// 	if (lpStream != NULL) {
// 		lpStream->lpVtbl->Release(lpStream);
// 		lpStream = NULL;
// 	}

// 	if (lpwOutput != NULL) {
// 		KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, lpwOutput);
// 	}

// 	return;
// }

const char* ConvertLpwstrToConstChar(LPWSTR lpwstr) {
    if (lpwstr == NULL) return NULL;

    // Get required size for destination buffer
    int sizeNeeded = Kernel32$WideCharToMultiByte(CP_UTF8, 0, lpwstr, -1, NULL, 0, NULL, NULL);
    if (sizeNeeded <= 0) return NULL;

    // Allocate memory
    char* buffer = (char*)MSVCRT$malloc(sizeNeeded);
    if (!buffer) return NULL;

    // Perform conversion
    Kernel32$WideCharToMultiByte(CP_UTF8, 0, lpwstr, -1, buffer, sizeNeeded, NULL, NULL);

    return buffer;  // You must free() this later
}

VOID go(IN PCHAR Args, IN ULONG Length) { 

	if(!bofstart())
	{
		return;
	}

	DWORD dwRet = 0;
	PDOMAIN_CONTROLLER_INFOW pdcInfo;

	// Get a Domain Controller for the Domain this computer is on.
	dwRet = NETAPI32$DsGetDcNameW(NULL, NULL, NULL, NULL, 0, &pdcInfo);
	if (ERROR_SUCCESS == dwRet) {
		// Open the enumeration.
		HANDLE hGetDc;
		dwRet = NETAPI32$DsGetDcOpenW(pdcInfo->DomainName,
			DS_NOTIFY_AFTER_SITE_RECORDS,
			NULL,
			NULL,
			NULL,
			0,
			&hGetDc);

		if (ERROR_SUCCESS == dwRet) {
			LPWSTR pszDnsHostName;

			// internal_printf("--------------------------------------------------------------------\n");
			// internal_printf("[+] DomainControllerName (PDC):\n");
			// internal_printf("    %ls\n", pdcInfo->DomainControllerName);

			// internal_printf("[+] DomainControllerAddress (PDC):\n");
			// internal_printf("    %ls\n", pdcInfo->DomainControllerAddress);

			// // Enumerate each Domain Controller and print its name.
			// internal_printf("[+] NextDc DnsHostName:\n");

			unsigned short type = 1;

			while (TRUE) {
				ULONG ulSocketCount;
				LPSOCKET_ADDRESS rgSocketAddresses;

				dwRet = NETAPI32$DsGetDcNextW(
					hGetDc, 
					&ulSocketCount, 
					&rgSocketAddresses, 
					&pszDnsHostName);

				if (ERROR_SUCCESS == dwRet) {
					// internal_printf("    %ls\n", pszDnsHostName);

					const char * dcHostName = ConvertLpwstrToConstChar(pszDnsHostName);

					query_domain(dcHostName, type, NULL);

					// Free the allocated string.
					NETAPI32$NetApiBufferFree(pszDnsHostName);

					// Free the socket address array.
					KERNEL32$LocalFree(rgSocketAddresses);
				}
				else if (ERROR_NO_MORE_ITEMS == dwRet) {
					// The end of the list has been reached.
					break;
				}
				else if (ERROR_FILEMARK_DETECTED == dwRet) {
					// DS_NOTIFY_AFTER_SITE_RECORDS was specified inmDsGetDcOpen and the end of the site-specific records was reached.
					internal_printf("[+] End of site-specific Domain Controllers.\n");
					continue;
				}
				else {
					// Some other error occurred.
					break;
				}
			}

			// internal_printf("--------------------------------------------------------------------\n");

			// Close the enumeration.
			NETAPI32$DsGetDcCloseW(hGetDc);

			//Print final Output
			// BeaconOutputStreamW();
		}

		// Free the DOMAIN_CONTROLLER_INFO structure.
		NETAPI32$NetApiBufferFree(pdcInfo);
	}
	printoutput(TRUE);
}
