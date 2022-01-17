#include <patterns/Hooking.h>
#include <patterns/Hooking.Patterns.h>
#include <Windows.h>

		// fwBoxStreamerVariable: relocate internal multi-node BVH traversal list and make it bigger (1000 limit is not enough
		// if having lots of mapdata with 'full-map-size' extents loaded that will always pass)
        // made originally by CitizenFX and this is part of FiveM I have just ported it into standalone asi/dll
		// https://github.com/citizenfx/fivem/blob/de2f238ab8d1a8041c9f5a0cae99299f9cb2a868/code/components/gta-streaming-five/src/UnkStuff.cpp#L339
        // i don't take any credits for this x)
void InitializeMod()
{

	auto mnbvhList = hook::AllocateStubMemory(4096 * 8);

	{
		// GetIntersectingAABB
		auto location = hook::get_pattern<char>("0F 28 0A 48 8B 49 08 4C 8D 25", 10);
		hook::put<int32_t>(location, (char*)mnbvhList - location + 4);
		hook::put<int32_t>(location + 31, 4004);
	}

	{
		// GetIntersectingLine
		auto location = hook::get_pattern<char>("48 8B 49 08 4C 8D 3D", 7);
		hook::put<int32_t>(location, (char*)mnbvhList - location + 4);
		hook::put<int32_t>(location + 8, 4004);
	}
}

BOOL WINAPI DllMain(_In_ void* _DllHandle, _In_ unsigned long _Reason, _In_opt_ void* _Reserved)
{
	if (_Reason == DLL_PROCESS_ATTACH)
	{
		InitializeMod();
	}

	return TRUE;
}
