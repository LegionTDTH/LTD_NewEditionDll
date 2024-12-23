#include "Header.h"

string V_DirWar3;

#define IsKeyPressed(CODE) (GetAsyncKeyState(CODE) & 0x8000) > 0

void LogItem(const char* Msg...)
{
	va_list arguments;
	va_start(arguments, Msg);

	int len = _vscprintf(Msg, arguments) + 1;
	char* text = new char[len];
	vsprintf_s(text, len, Msg, arguments);
	va_end(arguments);

	FILE* plik = nullptr;
	fopen_s(&plik, "LTD-Debug.log", "a");
	if (plik)
	{
		fprintf(plik, "%s\n", text);
		fclose(plik);
	}
	delete[] text;
}

DWORD dwVersion = 0;
static const DWORD CALL = 0xE8;
static const DWORD JUMP = 0xE9;
static const DWORD NOP = 0x90;
static const DWORD RET = 0xC3;
static const DWORD XOR = 0x33;
static const DWORD CUSTOM = 0;

enum Version
{
	v124e = 6387,
	v126a = 6401,
};

struct w3_version
{
	int v124e;
	int v126a;
};

enum FileDLL
{
	DDLL_GAME = 0,
	DDLL_STORM = 1,
	DDLL_D3D8 = 2,
	DDLL_D3D9 = 3,
	DDLL_LIB7B = 4,
	DDLL_LIB7C = 5,
	DDLL_LIB7E = 6,
};

const char* szGameDLL()
{
	if (dwVersion == v124e)
	{
		HMODULE hmod = GetModuleHandle("lib7C.dll");
		if (hmod)
			return "lib7C.dll";
	}

	if (dwVersion == v126a)
	{
		HMODULE hmod = GetModuleHandle("lib7E.dll");
		if (hmod)
			return "lib7E.dll";
	}

	return "Game.dll";
}

void WarcraftVersion()
{
	DWORD dwHandle = 0;
	DWORD dwLen = GetFileVersionInfoSize(szGameDLL(), &dwHandle);
	if (dwLen == 0)
		return;

	char* lpData = new char[dwLen];
	if (!GetFileVersionInfo(szGameDLL(), dwHandle, dwLen, lpData))
	{
		delete lpData;
		return;
	}

	VS_FIXEDFILEINFO* Version;
	UINT uLen = sizeof(VS_FIXEDFILEINFO);
	if (!VerQueryValue(lpData, "\\", (LPVOID *)&Version, &uLen))
	{
		delete lpData;
		return;
	}
	delete lpData;
	dwVersion = LOWORD(Version->dwFileVersionLS);
}

DWORD GetDllOffset(const char* dll, int offset)
{
	HMODULE hmod = GetModuleHandle(dll);
	if (!hmod)
		hmod = LoadLibrary(dll);

	if (!hmod) return 0;
	if (offset < 0)
		return (DWORD)GetProcAddress(hmod, (LPCSTR)(-offset));

	return ((DWORD)hmod) + offset;
}

DWORD GetDllOffsetEx(int num, int offset, int offset2)
{
	if (dwVersion <= 0)
		WarcraftVersion();

	if (dwVersion == v124e)
		return GetDllOffset(szGameDLL(), offset);

	if (dwVersion == v126a)
		return GetDllOffset(szGameDLL(), offset2);

	return 0;
}

BOOL WriteBytes(LPVOID pAddr, VOID * pData, DWORD dwLen)
{
	DWORD dwOld;

	if (!VirtualProtect(pAddr, dwLen, PAGE_READWRITE, &dwOld))
		return FALSE;

	memcpy(pAddr, pData, dwLen);
	return VirtualProtect(pAddr, dwLen, dwOld, &dwOld);
}

DWORD VirtualProtectEX(DWORD pAddress, DWORD len, DWORD prot)
{
	DWORD oldprot = 0;
	VirtualProtect((void*)pAddress, len, prot, &oldprot);
	return oldprot;
}

void WriteLocalBYTES(DWORD pAddress, void* buf, int len)
{
	DWORD oldprot = VirtualProtectEX(pAddress, len, PAGE_EXECUTE_READWRITE);
	WriteProcessMemory(GetCurrentProcess(), (void*)pAddress, buf, len, 0);
	VirtualProtectEX(pAddress, len, oldprot);
}

void PatchVALUE(DWORD addr, DWORD param, DWORD len)
{
	WriteLocalBYTES(addr, &param, len);
}

void Patch(BYTE bInst, const char* dll, DWORD pAddr, DWORD pFunc, DWORD dwLen, const char* Type)
{
	if (pAddr == 0) return;
	pAddr = GetDllOffset(dll, pAddr);
	BYTE *bCode = new BYTE[dwLen];
	if (bInst)
	{
		::memset(bCode, 0x90, dwLen);
		bCode[0] = bInst;
		if (pFunc)
		{
			if (bInst == 0xE8 || bInst == 0xE9)
			{
				DWORD dwFunc = pFunc - (pAddr + 5);
				*(DWORD*)&bCode[1] = dwFunc;
			}
			else if (bInst == 0x68 || bInst == 0x05 || bInst == 0x5B)
			{
				*(LPDWORD)&bCode[1] = pFunc;
			}
			else if (bInst == 0x83)
			{
				*(WORD*)&bCode[1] = (WORD)pFunc;
			}
			else
			{
				bCode[1] = (BYTE)pFunc;
			}
		}
	}
	else
	{
		if (dwLen == 6)
		{
			::memset(bCode, 0x00, dwLen);
			*(DWORD*)&bCode[0] = pFunc;
		}
		else if (dwLen == 4)
			*(DWORD*)&bCode[0] = pFunc;
		else if (dwLen == 3)
		{
			PatchVALUE(pAddr, pFunc, dwLen);
		}
		else if (dwLen == 2)
			*(WORD*)&bCode[0] = (WORD)pFunc;
		else if (dwLen == 1)
			*(BYTE*)&bCode[0] = (BYTE)pFunc;
		else {
			memcpy(bCode, (void*)pFunc, dwLen);
		}
	}

	if (!WriteBytes((void*)pAddr, bCode, dwLen))
	{
		delete[] bCode;
	}
	delete[] bCode;

	FlushInstructionCache(GetCurrentProcess(), (void*)pAddr, dwLen);
}

void PatchEx(BYTE bInst, const char* dll, w3_version pAddr, DWORD pFunc, DWORD dwLen, const char* Type)
{
	if (dwVersion <= 0)
		WarcraftVersion();

	if (dwVersion == v124e)
		Patch(bInst, dll, pAddr.v124e, pFunc, dwLen, Type);

	if (dwVersion == v126a)
		Patch(bInst, dll, pAddr.v126a, pFunc, dwLen, Type);
}

#pragma pack(1)
struct DataLTD
{
	int ELO;
	int Win;
	int Lose;
};

struct CTextFrame
{
	BYTE						baseControl[0x1E4];		//0x0
	uint32_t					textLength;				//0x1E4
	char*						text;					//0x1E8
};
#pragma pack()

map<string, DataLTD*> mName;
bool ismapltdng = false;

#define W3_FUNC(DLL, NAME, RETURN, CONV, ARGS, OFFSET, OFFSET2) typedef RETURN (CONV* DLL##_##NAME##_t) ARGS; __declspec(selectany) extern DLL##_##NAME##_t DLL##_##NAME = (DLL##_##NAME##_t)GetDllOffsetEx(DDLL_##DLL, OFFSET, OFFSET2);   ///
#define W3_VAR(DLL, NAME, TYPE, OFFSET, OFFSET2) typedef TYPE DLL##_##NAME##_vt; __declspec(selectany) extern DLL##_##NAME##_vt * DLL##_##NAME = (DLL##_##NAME##_vt *)GetDllOffsetEx(DDLL_##DLL, OFFSET, OFFSET2);                          ///

W3_FUNC(GAME, ChatSendEvent, int, __fastcall, (int GlobalGlueObjAddr, int zero, int event_vtable), 0x2FD240, 0x2FC700)
W3_FUNC(GAME, GameChatSetState, int, __fastcall, (int chat, int unused, BOOL IsOpened), 0x341FA0, 0x341460)
W3_FUNC(GAME, SetCamera, void, __thiscall, (int a1, int whichField, float Dis, float duration, int a5), 0x3065A0, 0x305A60)
W3_FUNC(GAME, GetPlayerName, char*, __thiscall, (int nPlayerId), 0x2F9AD0, 0x2F8F90)

W3_VAR(GAME, GetHwnd, HWND, 0xAE81F8, 0xAD1398)
W3_VAR(GAME, W3XGlobalClass, int*, 0xACBDD8, 0xAB4F80)
W3_VAR(GAME, IsChatBoxOpen, bool, 0xAE8450, 0xAD15F0)
W3_VAR(GAME, GlobalGlueObj, int, 0xAE54CC, 0xACE66C)
W3_VAR(GAME, EventVtable, int, 0xAB0CD0, 0xA9ACB0)
W3_VAR(GAME, MapNameOffset1, int, 0xAC55E0, 0xAAE788)

char* substr(char* arr, int begin, int len)
{
	char* res = new char[len + 1];
	for (int i = 0; i < len; i++)
		res[i] = *(arr + begin + i);
	res[len] = 0;
	return res;
}

int GetChatOffset()
{
	int pclass = *(int*)GAME_W3XGlobalClass;
	if (pclass > 0)
		return *(int*)(pclass + 0x3FC);

	return 0;
}

char* GetChatString()
{
	int pChatOffset = GetChatOffset();
	if (pChatOffset > 0)
	{
		pChatOffset = *(int*)(pChatOffset + 0x1E0);
		if (pChatOffset > 0)
		{
			pChatOffset = *(int*)(pChatOffset + 0x1E4);
			return (char*)pChatOffset;
		}
	}

	return 0;
}

void __stdcall SendMessageToChat(const char* msg, ...)
{
	if (!msg || msg[0] == '\0')
		return;

	char szBuffer[8192] = {};
	va_list Args;

	va_start(Args, msg);
	vsprintf(szBuffer, msg, Args);
	va_end(Args);

	int ChatOffset = GetChatOffset();
	if (!ChatOffset) return;

	char* pChatString = GetChatString();
	if (!pChatString) return;

	BlockInput(TRUE);

	if (*GAME_IsChatBoxOpen)
	{
		GAME_GameChatSetState(ChatOffset, 0, 0);
		GAME_GameChatSetState(ChatOffset, 0, 1);
	}
	else
	{
		GAME_GameChatSetState(ChatOffset, 0, 1);
	}

	sprintf(pChatString, "%.128s", szBuffer);
	GAME_ChatSendEvent(*GAME_GlobalGlueObj, 0, *GAME_EventVtable);

	BlockInput(FALSE);
}

W3_FUNC(GAME, SetTextFrameRace, void, __thiscall, (int* pThis, int nRace), 0x559D60, 0x559260)
W3_FUNC(GAME, SetTextFrameObs, void, __thiscall, (int* pThis), 0x559E20, 0x559320)
W3_FUNC(GAME, ChatRoomPlayerJoin, void, __thiscall, (int* pThis, int p38C), 0x57BD00, 0x57B060)
W3_FUNC(GAME, GetPlayerNameEx, const char*, __fastcall, (BYTE a1, int a2), 0x53F900, 0x53EE00)
W3_FUNC(GAME, sub_6F54FEF0, BYTE, __fastcall, (int pthis, int a2), 0x54FEF0, 0x54F3F0)
W3_FUNC(GAME, sub_6F53F8D0, BYTE, __fastcall, (int a1), 0x53F8D0, 0x53EDD0)
W3_FUNC(GAME, TextFrame_setText, void, __thiscall, (CTextFrame* t, const char* text), 0x6124E0, 0x611D40)

CTextFrame* __fastcall sub_6F61EFC0(int* pthis)
{
	return (CTextFrame*)pthis[0x79];
}

string __fastcall GetTextDataLTD(int* pThis)
{
	if (pThis && ismapltdng == true)
	{
		CTextFrame* pCTextFrameNamePlayer = sub_6F61EFC0(*(int**)(pThis[0x68] + 0x1E4));
		if (pCTextFrameNamePlayer)
		{
			if (pCTextFrameNamePlayer->text)
			{
				DataLTD* pData = mName[pCTextFrameNamePlayer->text];
				if (pData)
				{
					string szELO = "|cFFFFCC00ELO|r: |cFF1CE6B9" + to_string(pData->ELO);
					string szWIN = "|cFFFFCC00W|r: |cFF1CE6B9" + to_string(pData->Win);
					string szLose = "|cFFFFCC00L|r: |cFF1CE6B9" + to_string(pData->Lose);
					return szELO + " " + szWIN + " " + szLose;
				}
			}
		}
	}

	return "";
}

void __fastcall GAME_SetTextFrameRace_hook(int* pThis, int nothing, int nRace)
{
	string szText = GetTextDataLTD(pThis);
	if (szText.empty())
	{
		GAME_SetTextFrameRace(pThis, nRace);
		return;
	}

	if (pThis)
		GAME_TextFrame_setText(sub_6F61EFC0((int*)sub_6F61EFC0((int*)pThis[0x69])), szText.c_str());
}

void __fastcall GAME_SetTextFrameObs_hook(int* pThis, int nothing)
{
	string szText = GetTextDataLTD(pThis);
	if (szText.empty())
	{
		GAME_SetTextFrameObs(pThis);
		return;
	}

	if (pThis)
		GAME_TextFrame_setText(sub_6F61EFC0(*(int**)(pThis[0x69] + 0x1E4)), szText.c_str());
}

void __fastcall GAME_ChatRoomPlayerJoin_Hook(int* pThis, int nothing, int p38C)
{
	GAME_ChatRoomPlayerJoin(pThis, p38C);

	if (p38C && ismapltdng == true)
	{
		const char* szName = GAME_GetPlayerNameEx(GAME_sub_6F54FEF0(*(BYTE*)(p38C + 0x14), *(int*)(p38C + 0x10)), 0);
		if (szName)
		{
			DataLTD* pData = new DataLTD();
			mName[szName] = pData;
		}
	}

	if (pThis)
	{
		const char* szNameMe = GAME_GetPlayerNameEx(GAME_sub_6F53F8D0(pThis[90]), pThis[90]);
		if (szNameMe && mName[szNameMe] == nullptr)
		{
			DataLTD* pData = new DataLTD();
			mName[szNameMe] = pData;
		}
	}
}

void __fastcall TextFrame_setText_0x3C8(CTextFrame *pCTextFrame, int edx, const char *szText)
{
	ismapltdng = false;
	if (szText)
	{
		string szMapName = szText;
		if (
			szMapName.find("LTD") != string::npos ||
			(szMapName.find("Legion") != string::npos && szMapName.find("TD") != string::npos && szMapName.find("NewEdition") != string::npos)
			)
			ismapltdng = true;
	}

	GAME_TextFrame_setText(pCTextFrame, szText);
}

int __stdcall LTD_AutoLoadCode(char* szName)
{
	CreateFolder(V_DirWar3);
	
	string code;
	char line[8000] = {};
	string szFile = V_DirWar3 + "\\SaveCode_" + string(szName) + ".txt";
	FILE* pFile = fopen(szFile.c_str(), "r");
	if (!pFile) return 0;

	while (fgets(line, 8000, pFile))
	{
		string input = line;
		std::string prefix = "-load ";
		size_t startPos = input.find(prefix);
		if (startPos != std::string::npos) 
		{
			size_t endPos = input.find("\"", startPos);
			if (endPos != std::string::npos) 
			{
				code = input.substr(startPos, endPos - startPos);
				break;
			}
		}
	}
	fclose(pFile);
	if (code.length() > 0)
	{
		SendMessageToChat("%s", code.c_str());
		DeleteFile(szFile.c_str());
	}
	return 1;
}

BOOL __stdcall DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
	switch (fdwReason)
	{
		case DLL_PROCESS_ATTACH:
		{
			DisableThreadLibraryCalls(hinstDLL);
			char filename[4096] = {};
			GetCurrentDirectory(4096, filename);
			V_DirWar3.assign(filename);
			V_DirWar3 += "\\NewEdition";
			CreateFolder(V_DirWar3);
			if (dwVersion <= 0)
				WarcraftVersion();

			PatchEx(CALL, szGameDLL(), { 0x59B851, 0x59B0B1 }, (DWORD)TextFrame_setText_0x3C8, 5, "");
			PatchEx(CALL, szGameDLL(), { 0x5B755C, 0x5B6DBC }, (DWORD)GAME_ChatRoomPlayerJoin_Hook, 5, "");
			PatchEx(CALL, szGameDLL(), { 0x5619F6, 0x560EF6 }, (DWORD)GAME_SetTextFrameRace_hook, 5, "");
			PatchEx(CALL, szGameDLL(), { 0x561A10, 0x560F10 }, (DWORD)GAME_SetTextFrameObs_hook, 5, "");
			break;
		}
		case DLL_PROCESS_DETACH:
		{

			break;
		}
	}

	return TRUE;
}