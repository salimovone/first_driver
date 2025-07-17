#include <iostream>
#include <Windows.h>
#include <TlHelp32.h>

using namespace std;

static DWORD get_process_id(const wchar_t* process_name) {
	DWORD process_id = 0;

	HANDLE snap_shot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
	if (snap_shot == INVALID_HANDLE_VALUE) return process_id;

	PROCESSENTRY32 entry = {};
	entry.dwSize = sizeof(decltype(entry));
	if (Process32FirstW(snap_shot, &entry) == TRUE) { 
		if (_wcsicmp(process_name, entry.szExeFile) == 0) {
			process_id = entry.th32ProcessID;
		}
		else {
			while (Process32NextW(snap_shot, &entry) == TRUE) {
				if (_wcsicmp(process_name, entry.szExeFile) == 0) {
					process_id = entry.th32ProcessID;
					break;
				}
			}
		}
	}

	CloseHandle(snap_shot);

	return process_id;
}

static uintptr_t get_module_base(const DWORD pid, const wchar_t* module_name) {
	uintptr_t module_base = 0;

	HANDLE snap_shot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
	if (snap_shot == INVALID_HANDLE_VALUE) return module_base;

	MODULEENTRY32W entry = {};
	entry.dwSize = sizeof(decltype(entry));

	if (Module32FirstW(snap_shot, &entry) == TRUE) {
		if (wcsstr(module_name, entry.szModule) != nullptr) 
			module_base = reinterpret_cast<uintptr_t>(entry.modBaseAddr);
		else {
			while (Module32NextW(snap_shot, &entry) == TRUE) {
				if (wcsstr(module_name, entry.szModule) != nullptr) {
					module_base = reinterpret_cast<uintptr_t>(entry.modBaseAddr);
					break;
				}
			}
		}
	}

	CloseHandle(snap_shot);

	return module_base;
}

namespace driver {
	namespace codes {
		// used to setup the driver
		constexpr ULONG attach = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x696, METHOD_BUFFERED, FILE_SPECIAL_ACCESS);

		// read process memory
		constexpr ULONG read = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x697, METHOD_BUFFERED, FILE_SPECIAL_ACCESS);

		// write process memory
		constexpr ULONG write = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x698, METHOD_BUFFERED, FILE_SPECIAL_ACCESS);
	}

	// shared memory between user and kernel mode
	struct Request
	{
		HANDLE process_id; // process id to read/write memory from/to

		PVOID target;
		PVOID buffer;

		SIZE_T size;
		SIZE_T return_size;
	};

	bool attach_to_process(HANDLE driver_handle, const DWORD pid) {
		Request r;

		r.process_id = reinterpret_cast<HANDLE>(pid);

		return DeviceIoControl(driver_handle, codes::attach, &r, sizeof(r), &r, sizeof(r), nullptr, nullptr);
	}

	template<typename T>
	T read_memory(HANDLE driver_handle, const uintptr_t addr) {
		T temp = {};

		Request r;
		r.target = reinterpret_cast<PVOID>(addr);
		r.buffer = &temp;
		r.size = sizeof(T);

		DeviceIoControl(driver_handle, codes::read, &r, sizeof(r), &r, sizeof(r), nullptr, nullptr); 

		return temp;
	}

	template<typename T>
	void write_memory(HANDLE driver_handle, const uintptr_t addr, const T& value) {
		Request r;
		r.target = reinterpret_cast<PVOID>(addr);
		r.buffer = (PVOID)&value;
		r.size = sizeof(T);

		DeviceIoControl(driver_handle, codes::write, &r, sizeof(r), &r, sizeof(r), nullptr, nullptr); 
	}

}

int main() {
	const DWORD pid = get_process_id(L"notepad.exe");	
	
	if (pid == 0) {
		cout << "Failed to find notepad.exe" << endl;
		cin.get();
		return 1;
	}

	const HANDLE driver = CreateFile(L"\\\\.\\MyDriver", GENERIC_READ, 0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);

	if (driver == INVALID_HANDLE_VALUE) {
		cout << "Failed to create our driver handle" << endl;
		cin.get();
		return 1;
	}

	if (driver::attach_to_process(driver, pid) == true) {
		cout << "Attachment Successful" << endl;
	}

	CloseHandle(driver);
	cin.get();
	return 0;
}