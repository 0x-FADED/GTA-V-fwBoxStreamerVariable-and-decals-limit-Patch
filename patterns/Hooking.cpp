#include "Hooking.h"
#include <Windows.h>
#include <cassert>
#include <memory>

namespace hook
{

	//http://stackoverflow.com/questions/4840410/how-to-align-a-pointer-in-c
	/* Align upwards -  arithmetic mode */
	static inline ULONG_PTR AlignUp(ULONG_PTR stack, size_t align)
	{
		assert(align > 0 && (align & (align - 1)) == 0); // Power of 2 
		assert(stack != 0);

		auto addr = stack;
		if (addr % align != 0)
			addr += align - (addr % align);
		assert(addr >= stack);
		return addr;
	}
	/* Align downwards - bit mask mode */
	static inline ULONG_PTR AlignDown(ULONG_PTR stack, size_t align)
	{
		assert(align > 0 && (align & (align - 1)) == 0); // Power of 2 
		assert(stack != 0);

		auto addr = stack;
		addr &= -align; // Round down to align-byte boundary
		assert(addr <= stack);
		return addr;
	}
	size_t GetAllocationAlignment()
	{
		SYSTEM_INFO info;
		memset(&info, 0, sizeof(info));
		GetSystemInfo(&info);
		return info.dwAllocationGranularity;
	}
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
		
		auto alignment = GetAllocationAlignment();
		auto start = AlignUp(minAddr, alignment);
		auto end = AlignDown(maxAddr, alignment);

		addressReqs.Alignment = NULL; // any alignment
		addressReqs.LowestStartingAddress = (PVOID)start < si.lpMinimumApplicationAddress ? si.lpMinimumApplicationAddress : (PVOID)start;
		addressReqs.HighestEndingAddress = (PVOID)(end - 1) > si.lpMaximumApplicationAddress ? si.lpMaximumApplicationAddress : (PVOID)(end - 1);

		param.Type = MemExtendedParameterAddressRequirements;
		param.Pointer = &addressReqs;

		auto hModule = GetModuleHandle("kernelbase.dll");
		if (hModule == nullptr)
		{
			hModule = LoadLibrary("kernelbase.dll");
		}

		//using VirtualAlloc2 throws linker error gotta either use this workaround or use #pragma comment(lib, "mincore") to get it to work
		auto pVirtualAlloc2 = (decltype(&::VirtualAlloc2))GetProcAddress(hModule, "VirtualAlloc2");

		void* stub = nullptr;

		stub = pVirtualAlloc2(GetCurrentProcess(), NULL, size, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE, &param, 1);

		return stub;
	}
}
