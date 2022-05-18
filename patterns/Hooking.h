#pragma once
#include <stdint.h>
#include <type_traits>
#include <windows.h>
/*
 * This file is part of the CitizenFX project - http://citizen.re/
 *
 * See LICENSE and MENTIONS in the root of the source tree for information
 * regarding licensing.
 *
 * https://github.com/citizenfx/fivem/blob/master/code/client/shared/Hooking.h
 */

namespace hook
{
	template<typename ValueType, typename AddressType>
	inline void put(AddressType address, ValueType value)
	{
		DWORD oldProtect;
		VirtualProtect((void*)address, sizeof(value), PAGE_EXECUTE_READWRITE, &oldProtect);

		memcpy((void*)address, &value, sizeof(value));

		VirtualProtect((void*)address, sizeof(value), oldProtect, &oldProtect);

		FlushInstructionCache(GetCurrentProcess(), (void*)address, sizeof(value));
	}

	void* AllocateStubMemory(size_t size);

	template<typename T, typename TAddr>
	inline T get_address(TAddr address)
	{
		intptr_t target = *(int32_t*)(ptrdiff_t(address));
		target += (ptrdiff_t(address) + 4);

		return (T)target;
	}
}