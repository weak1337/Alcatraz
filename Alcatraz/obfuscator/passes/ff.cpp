#include "../obfuscator.h"

bool obfuscator::obfuscate_ff(std::vector<obfuscator::function_t>::iterator& function, std::vector<obfuscator::instruction_t>::iterator& instruction) {

	instruction_t conditional_jmp{}; conditional_jmp.load(function->func_id, { 0xEB });
	conditional_jmp.isjmpcall = false;
	conditional_jmp.has_relative = false;
	instruction = function->instructions.insert(instruction, conditional_jmp);
	instruction++;
}