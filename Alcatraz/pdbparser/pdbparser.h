#pragma once
#include "../pe/pe.h"

#include <string>

class pdbparser {
private:

	struct codeviewInfo_t
	{
		ULONG CvSignature;
		GUID Signature;
		ULONG Age;
		char PdbFileName[ANYSIZE_ARRAY];
	};

	uint8_t* module_base;

	std::string binary_path;

public:

	struct sym_func {
		uint32_t offset;
		std::string name;
		uint32_t size;
	};

	pdbparser(pe64* pe, std::string binary_path);
	
	~pdbparser();

	std::vector<sym_func>parse_functions();

};