#include "../obfuscator.h"

#include <random>

using namespace asmjit;
bool obfuscator::obfuscsate_lea(std::vector<obfuscator::function_t>::iterator& function, std::vector<obfuscator::instruction_t>::iterator& instruction) {


	auto x86_register_map = lookupmap.find(instruction->zyinstr.operands[0].reg.value);

	if (x86_register_map != lookupmap.end()) {
		switch (instruction->relative.size) {

		case 32:

			std::random_device rd;
			std::default_random_engine generator(rd());
			std::uniform_int_distribution<uint32_t>distribution(INT32_MAX / 2, INT32_MAX);
			auto rand_add_val = distribution(generator);

			instruction->location_of_data += rand_add_val;
			JitRuntime rt;
			CodeHolder code;
			code.init(rt.environment());
			x86::Assembler a(&code);

			a.pushf();
			a.sub(x86_register_map->second, rand_add_val);
			a.popf();

			void* fn;
			auto err = rt.add(&fn, &code);
			auto jitinstructions = this->instructions_from_jit((uint8_t*)fn, code.codeSize());


			for (auto jit : jitinstructions) {
				instruction = function->instructions.insert(instruction + 1, jit);
			}

			rt.release(fn);
			break;
			
		}
	}
	

	return true;
}