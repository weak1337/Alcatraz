#include "pdbparser.h"

#include <Windows.h>
#define _NO_CVCONST_H 
#include <dbghelp.h>
#include <filesystem>
#include <algorithm>

#pragma comment(lib, "dbghelp.lib")

pdbparser::pdbparser(pe64* pe) {

	if (!SymInitialize(GetCurrentProcess(), nullptr, false))
		throw std::runtime_error("SymInitialize failed!");

	std::string binary_path = pe->get_path();

	auto debug_directory = pe->get_nt()->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress;

	std::string pdb_path = "";
	if(!debug_directory)
	{
		std::filesystem::path ppdb_path = binary_path;
		ppdb_path.replace_extension(".pdb");
		pdb_path = ppdb_path.string();
		if (!std::filesystem::exists(pdb_path))
		{
			throw std::runtime_error("No linked pdb file. Tried to find " + std::string(pdb_path.c_str()) + " without success");
		}
	}

	for (auto current_debug_dir = reinterpret_cast<IMAGE_DEBUG_DIRECTORY*>(pe->get_buffer()->data() + debug_directory); current_debug_dir->SizeOfData; current_debug_dir++) {
		
		if (current_debug_dir->Type != IMAGE_DEBUG_TYPE_CODEVIEW)
			continue;

		auto codeview_info = 
			reinterpret_cast<codeviewInfo_t*>(pe->get_buffer_not_relocated()->data() + current_debug_dir->PointerToRawData);

		std::string pdb_path = codeview_info->PdbFileName;
		if (!std::filesystem::exists(codeview_info->PdbFileName))
		{

			std::filesystem::path ppdb_path = binary_path;
			ppdb_path.replace_extension(".pdb");
			pdb_path = ppdb_path.string();
			if (!std::filesystem::exists(pdb_path))
			{
				throw std::runtime_error("Couldn't find linked pdb file. Tried to find " + std::string(pdb_path.c_str()) + " without success");
			}

		}

		this->module_base = 
			reinterpret_cast<uint8_t*>(SymLoadModuleEx(GetCurrentProcess(), 0, pdb_path.c_str(), 0, 0x10000000, static_cast<std::uint32_t>(std::filesystem::file_size(pdb_path)), 0, 0));

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

	std::vector<uint32_t>already_added;

	callb_str callbstr;
	callbstr.base = reinterpret_cast<DWORD64>(this->module_base);
	callbstr.collector = &functions;
	static int iterator = 0;
	const auto collect_callback =
		[](PSYMBOL_INFO psym_info, ULONG sym_size, PVOID collector) {
		if (psym_info->Tag == SymTagFunction) {

			callb_str* callbstr = reinterpret_cast<callb_str*>(collector);

			sym_func new_function{};
			auto status = 
				SymGetTypeInfo(GetCurrentProcess(), callbstr->base, psym_info->Index, TI_GET_OFFSET, &new_function.offset);

			if (!status)
				SymGetTypeInfo(GetCurrentProcess(), callbstr->base, psym_info->Index, TI_GET_ADDRESSOFFSET, &new_function.offset);

			auto elem = std::find_if(callbstr->collector->begin(), callbstr->collector->end(), [&](const sym_func func) {return func.offset == new_function.offset; });

			if (elem == callbstr->collector->end()) {
				new_function.id = iterator++;
				new_function.name = psym_info->Name;
				new_function.size = psym_info->Size;

				callbstr->collector->push_back(new_function);
			}

		
		}
		return TRUE;
	};

	if(!SymEnumSymbols(GetCurrentProcess(), reinterpret_cast<DWORD64>(this->module_base), NULL, (PSYM_ENUMERATESYMBOLS_CALLBACK)collect_callback, &callbstr))
		throw std::runtime_error("couldn't enum symbols");

	return functions;
}