#pragma once
#include "../pe/pe.h"
#include "Zydis/Zydis.h"
#include "../pdbparser/pdbparser.h"

#include <string>

class obfuscator {
private:

	pe64* pe;

	static int instruction_id;

	struct instruction_t {

		int inst_id;
		int func_id;
		bool is_first_instruction;
		std::vector<uint8_t>raw_bytes;
		uint64_t runtime_address;
		uint64_t relocated_address;
		ZydisDecodedInstruction zyinstr;
		bool has_relative;
		bool isjmpcall;

		struct {
			int target_inst_id;
			int target_func_id;
			uint32_t offset;
			uint32_t size;
		}relative;

		uint64_t location_of_data;

		void load_relative_info();
		void load(int funcid, std::vector<uint8_t>raw_data);
		void load(int funcid, ZydisDecodedInstruction zyinstruction, uint64_t runtime_address);
		void reload();
		void print();
	};

	struct function_t {
		int func_id;
		std::string name;
		std::vector<instruction_t>instructions;
		uint32_t offset;
		uint32_t size;

		function_t(int func_id, std::string name, uint32_t offset, uint32_t size) : func_id(func_id), name(name), offset(offset), size(size) {};

	};

	std::vector<function_t>functions;

	uint32_t total_size_used;

	bool find_inst_at_dst(uint64_t dst, instruction_t** instptr, function_t** funcptr);

	void remove_jumptables();

	bool analyze_functions();

	void relocate(PIMAGE_SECTION_HEADER new_section);

	bool find_instruction_by_id(int funcid, int instid, instruction_t* inst);

	bool fix_relative_jmps(function_t* func);

	bool convert_relative_jmps();

	bool apply_relocations(PIMAGE_SECTION_HEADER new_section);

	void compile(PIMAGE_SECTION_HEADER new_section);

public:

	obfuscator(pe64* pe);

	void create_functions(std::vector<pdbparser::sym_func>functions);

	void run(PIMAGE_SECTION_HEADER new_section);

	uint32_t get_added_size();

};