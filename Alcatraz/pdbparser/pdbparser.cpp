#include "pdbparser.h"

#include <Windows.h>
#define _NO_CVCONST_H 
#include <dbghelp.h>
#include <filesystem>

#pragma comment(lib, "dbghelp.lib")

pdbparser::pdbparser(pe64* pe) {

	if (!SymInitialize(GetCurrentProcess(), nullptr, false))
		throw std::runtime_error("SymInitialize failed!");

	auto debug_directory = pe->get_nt()->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress;

	if(!debug_directory)
		throw std::runtime_error("no pdb path linked!");


	for (auto current_debug_dir = reinterpret_cast<IMAGE_DEBUG_DIRECTORY*>(pe->get_buffer()->data() + debug_directory); current_debug_dir->SizeOfData; current_debug_dir++) {
		
		if (current_debug_dir->Type != IMAGE_DEBUG_TYPE_CODEVIEW)
			continue;

		auto codeview_info = 
			reinterpret_cast<codeviewInfo_t*>(pe->get_buffer_not_relocated()->data() + current_debug_dir->PointerToRawData);

		if(!std::filesystem::exists(codeview_info->PdbFileName))
			throw std::runtime_error("couldn't find linked pdb file!");

		this->module_base = 
			reinterpret_cast<uint8_t*>(SymLoadModuleEx(GetCurrentProcess(), 0, codeview_info->PdbFileName, 0, 0x10000000, static_cast<std::uint32_t>(std::filesystem::file_size(codeview_info->PdbFileName)), 0, 0));

		if(!this->module_base)
			throw std::runtime_error("SymLoadModuleEx failed!");

		return;
		
	}

	throw std::runtime_error("unexpected error during pdbparser setup");
}

pdbparser::~pdbparser() {
	SymCleanup(GetCurrentProcess());
}

std::vector<pdbparser::sym_func>pdbparser::parse_functions() {

	struct callb_str {
		DWORD64 base;
		std::vector<sym_func>* collector;
	};

	std::vector<sym_func>functions;

	callb_str callbstr;
	callbstr.base = reinterpret_cast<DWORD64>(this->module_base);
	callbstr.collector = &functions;

	const auto collect_callback =
		[](PSYMBOL_INFO psym_info, ULONG sym_size, PVOID collector) {
		if (psym_info->Tag == SymTagFunction) {

			callb_str* callbstr = reinterpret_cast<callb_str*>(collector);

			sym_func new_function{};

			auto status = 
				SymGetTypeInfo(GetCurrentProcess(), callbstr->base, psym_info->Index, TI_GET_OFFSET, &new_function.offset);

			if (!status)
				SymGetTypeInfo(GetCurrentProcess(), callbstr->base, psym_info->Index, TI_GET_ADDRESSOFFSET, &new_function.offset);

			new_function.name = psym_info->Name;
			new_function.size = psym_info->Size;

			callbstr->collector->push_back(new_function);
		}
		return TRUE;
	};

	if(!SymEnumSymbols(GetCurrentProcess(), reinterpret_cast<DWORD64>(this->module_base), NULL, (PSYM_ENUMERATESYMBOLS_CALLBACK)collect_callback, &callbstr))
		throw std::runtime_error("couldn't enum symbols");

	return functions;
}