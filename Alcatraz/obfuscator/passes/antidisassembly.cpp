#include "../obfuscator.h"

bool obfuscator::obfuscate_ff(std::vector<obfuscator::function_t>::iterator& function, std::vector<obfuscator::instruction_t>::iterator& instruction) {

	instruction_t conditional_jmp{}; conditional_jmp.load(function->func_id, { 0xEB });
	conditional_jmp.isjmpcall = false;
	conditional_jmp.has_relative = false;
	instruction = function->instructions.insert(instruction, conditional_jmp);
	instruction++;

	return true;
}

bool obfuscator::add_junk(std::vector<obfuscator::function_t>::iterator& function, std::vector<obfuscator::instruction_t>::iterator& instruction) {

	//This has a weird bug. Going to fix
	
	/*
	instruction_t jz{}; jz.load(function->func_id, { 0x74, 0x3 });
	instruction_t jnz{}; jnz.load(function->func_id, { 0x75, 0x1 });
	instruction_t garbage{}; garbage.load(function->func_id, { 0xE8 });
	instruction_t nop{}; nop.load(function->func_id, { 0x90 });
	garbage.zyinstr = nop.zyinstr;
	garbage.has_relative = false;
	garbage.isjmpcall = false;

	instruction = function->instructions.insert(instruction, jz);
	instruction = function->instructions.insert(instruction + 1, jnz);
	instruction = function->instructions.insert(instruction + 1, garbage);

	(instruction - 2)->relative.target_func_id = function->func_id;
	(instruction - 1)->relative.target_func_id = function->func_id;

	(instruction - 2)->relative.target_inst_id = (instruction + 1)->inst_id;
	(instruction - 1)->relative.target_inst_id = (instruction + 1)->inst_id;
	
	instruction++;
	*/
	return true;

}