#include "nvse/PluginAPI.h"

NVSEInterface* g_nvseInterface{};

void SafeWrite8(UInt32 addr, UInt32 data)
{
	UInt32	oldProtect;

	VirtualProtect((void*)addr, 4, PAGE_EXECUTE_READWRITE, &oldProtect);
	*((UInt8*)addr) = data;
	VirtualProtect((void*)addr, 4, oldProtect, &oldProtect);
}

void SafeWrite16(UInt32 addr, UInt32 data)
{
	UInt32	oldProtect;

	VirtualProtect((void*)addr, 4, PAGE_EXECUTE_READWRITE, &oldProtect);
	*((UInt16*)addr) = data;
	VirtualProtect((void*)addr, 4, oldProtect, &oldProtect);
}

void SafeWrite32(UInt32 addr, UInt32 data)
{
	UInt32	oldProtect;

	VirtualProtect((void*)addr, 4, PAGE_EXECUTE_READWRITE, &oldProtect);
	*((UInt32*)addr) = data;
	VirtualProtect((void*)addr, 4, oldProtect, &oldProtect);
}

void PatchMemoryNop(ULONG_PTR Address, SIZE_T Size)
{
	DWORD d = 0;
	VirtualProtect((LPVOID)Address, Size, PAGE_EXECUTE_READWRITE, &d);

	for (SIZE_T i = 0; i < Size; i++)
		*(volatile BYTE*)(Address + i) = 0x90; //0x90 == opcode for NOP

	VirtualProtect((LPVOID)Address, Size, d, &d);

	FlushInstructionCache(GetCurrentProcess(), (LPVOID)Address, Size);
}

void SafeWriteBuf(UInt32 addr, const char* data, UInt32 len)
{
	UInt32	oldProtect;

	VirtualProtect((void*)addr, len, PAGE_EXECUTE_READWRITE, &oldProtect);
	memcpy((void*)addr, data, len);
	VirtualProtect((void*)addr, len, oldProtect, &oldProtect);
}

void WriteRelJump(UInt32 jumpSrc, UInt32 jumpTgt)
{
	// jmp rel32
	SafeWrite8(jumpSrc, 0xE9);
	SafeWrite32(jumpSrc + 1, jumpTgt - jumpSrc - 1 - 4);
}

bool NVSEPlugin_Query(const NVSEInterface* nvse, PluginInfo* info)
{
	info->infoVersion = PluginInfo::kInfoVersion;
	info->name = "HighResBloom";
	info->version = 5;

	return true;
}

bool NVSEPlugin_Load(NVSEInterface* nvse)
{
	char iniDir[MAX_PATH];
	GetModuleFileNameA(GetModuleHandle(NULL), iniDir, MAX_PATH);
	strcpy((char*)(strrchr(iniDir, '\\') + 1), "Data\\NVSE\\Plugins\\HighResBloom.ini");
	int  resScale = GetPrivateProfileInt("Main", "iResScale", 2, iniDir);
	bool bDisableBloom = GetPrivateProfileInt("Main", "bDisableBloom", 0, iniDir);
	bool useSquareBloom = GetPrivateProfileInt("BloomOptions", "bUseSquareBloom", 0, iniDir);
	bool useWidth = GetPrivateProfileInt("BloomOptions", "bUseWidth", 0, iniDir);
	bool customRes = GetPrivateProfileInt("Advanced", "bUseCustomRes", 0, iniDir);
	int width = GetPrivateProfileInt("Advanced", "iWidth", 1280, iniDir);
	int height = GetPrivateProfileInt("Advanced", "iHeight", 720, iniDir);
	UInt32 addressWidth, addressHeight, addressResCheck, addressCustomHeight, addressCustomWidth, addressSquareWidth, addressSquareHeight;

	if (resScale < 1)
		resScale = 1;

	if (width < 1)
		width = 1;

	if (height < 1)
		height = 1;

	if (!nvse->isEditor) {
		addressWidth = 0xB6C3DB;
		addressHeight = 0xB6C42E;
		addressResCheck = 0xB6C327;
		addressCustomHeight = 0xB6C44E;
		addressCustomWidth = 0xB6C454;
		addressSquareWidth = 0xB6C420;
		addressSquareHeight = 0xB6C3D1;

		if (bDisableBloom)
			WriteRelJump(0xBAE379, 0xBAE3E7);
	}
	else {
		addressWidth = 0x90574B;
		addressHeight = 0x90579E;
		addressResCheck = 0x905697;
		addressCustomHeight = 0x9057BE;
		addressCustomWidth = 0x9057C4;
		addressSquareWidth = 0x905790;
		addressSquareHeight = 0x905741;
	}

	if (customRes) {
		SafeWriteBuf(addressResCheck, "\xE9\x16\x01\x00\x00\x90", 6);
		SafeWrite16(addressCustomHeight + 2, height);
		SafeWrite16(addressCustomWidth + 2, width);
	}
	else {
		if (useSquareBloom) {
			if (useWidth) {
				SafeWriteBuf(addressSquareWidth, "\x8B\x82\x8C\x00\x00\x00", 6);
			}
			else {
				SafeWriteBuf(addressSquareHeight, "\x8B\x82\x90\x00\x00\x00", 6);
			}
		}

		SafeWrite8(addressResCheck - 3, 0x1); // Disable forced 256x256 on screen width 1280<=

		// Addresses for the values themselves

		switch (resScale) {
		default:
		case 1:
			PatchMemoryNop(addressWidth, 3); // Width
			PatchMemoryNop(addressHeight, 3); // Height
			break;
		case 2:
			SafeWrite8(addressWidth + 2, 1);
			SafeWrite8(addressHeight + 2, 1);
			break;
		case 4:
			SafeWrite8(addressWidth + 2, 2);
			SafeWrite8(addressHeight + 2, 2);
			break;
		case 8:
			SafeWrite8(addressWidth + 2, 3);
			SafeWrite8(addressHeight + 2, 3);
			break;
		}
	}

	return true;
}