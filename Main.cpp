#include <cstdio>
#include "VulnDriver/VulnDriver.hpp"

int main()
{
	printf("RTCore64 Kernel R/W\n");

	StatusCode status = gVulnDriver.Init();
	if (status != STATUS_SUCCESS)
	{
		printf("Driver init failed: %u\n", status);
		return 1;
	}

	printf("Driver loaded\n");

	/*
	* - Read Memory
	* uintptr_t KernelBase = 0xFFFFF80000000000;
	* gVulnDriver.Read<uint16_t>(KernelBase);
	*/

    /*
	* - Write Memory
	* uint8_t value = 0x90;
	* gVulnDriver.Write<uint8_t>(SomeAddress, value);
	*/

	printf("Press Enter to unload driver\n");
	getchar();

	gVulnDriver.Close();
	printf("Driver unloaded\n");

	return 0;
}
