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

	struct sym_func {
		uint32_t offset;
		std::string name;
		uint32_t size;
	};

	uint8_t* module_base;

public:

	pdbparser(pe64* pe);
	
	~pdbparser();

	std::vector<sym_func>parse_functions();

};