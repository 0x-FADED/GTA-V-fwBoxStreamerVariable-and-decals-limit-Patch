#include "Hooking.h"
#include <Windows.h>

namespace hook
{

	// Max range for seeking a memory block. (= 1024MB)
	const uint64_t MAX_MEMORY_RANGE = 0x40000000;

	void* AllocateStubMemory(size_t size)
	{
		void* origin = GetModuleHandle(NULL);

		ULONG_PTR minAddr;
		ULONG_PTR maxAddr;

		MEM_ADDRESS_REQUIREMENTS addressReqs = { 0 };
		MEM_EXTENDED_PARAMETER param = { 0 };

		SYSTEM_INFO si;
		GetSystemInfo(&si);
		minAddr = (ULONG_PTR)si.lpMinimumApplicationAddress;
		maxAddr = (ULONG_PTR)si.lpMaximumApplicationAddress;


		// origin ± 512MB
		if ((ULONG_PTR)origin > MAX_MEMORY_RANGE && minAddr < (ULONG_PTR)origin - MAX_MEMORY_RANGE)
			minAddr = (ULONG_PTR)origin - MAX_MEMORY_RANGE;

		if (maxAddr > (ULONG_PTR)origin + MAX_MEMORY_RANGE)
			maxAddr = (ULONG_PTR)origin + MAX_MEMORY_RANGE;


		addressReqs.Alignment = NULL; 
		addressReqs.LowestStartingAddress = (PVOID)minAddr < si.lpMinimumApplicationAddress ? si.lpMinimumApplicationAddress : (PVOID)minAddr;
		addressReqs.HighestEndingAddress = (PVOID)(maxAddr - 1) > si.lpMaximumApplicationAddress ? si.lpMaximumApplicationAddress : (PVOID)(maxAddr - 1);

		param.Type = MemExtendedParameterAddressRequirements;
		param.Pointer = &addressReqs;

		auto hModule = GetModuleHandle("kernelbase.dll");
		if (hModule == nullptr)
		{
			hModule = LoadLibrary("kernelbase.dll");
		}

		//using VirtualAlloc2 throws linker error gotta either use this workaround or use #pragma comment(lib, "mincore") to get it to work
		auto pVirtualAlloc2 = (decltype(&::VirtualAlloc2))GetProcAddress(hModule, "VirtualAlloc2");

		LPVOID pAlloc = origin;

		void* stub = nullptr;

		stub = pVirtualAlloc2(GetCurrentProcess(), NULL, size, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE, &param, 1);

		return stub;
	}
}
