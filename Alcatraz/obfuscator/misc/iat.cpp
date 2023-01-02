#include "../obfuscator.h"

#include <algorithm>

bool obfuscator::obfuscate_iat_call(std::vector<obfuscator::function_t>::iterator& func, std::vector<obfuscator::instruction_t>::iterator& instruction) {


//	printf("IAT CALL AT %x\n", instruction->runtime_address - (uint64_t)pe->get_buffer()->data());


	return true;
}