#include "../obfuscator.h"

#include <unordered_map>

#include <random>



bool obfuscator::obfuscate_constant(std::vector<obfuscator::function_t>::iterator& function,std::vector<obfuscator::instruction_t>::iterator& instruction) {


	auto x86_register_map = lookupmap.find(instruction->zyinstr.operands[0].reg.value);

	if (x86_register_map != lookupmap.end()) {

		int bit_of_value = instruction->zyinstr.raw.imm->size;

		auto usingregister = x86_register_map->second;

		//If the datatype doesnt match the register we skip it due to our rotations. You could translate to that register but meh
		if (bit_of_value == 8 && !usingregister.isGpb())
			return false;

		if (bit_of_value == 16 && !usingregister.isGpw())
			return false;

		if (bit_of_value == 32 && !usingregister.isGpd())
			return false;

		if (bit_of_value == 64 && !usingregister.isGpq())
			return false;
		

		std::random_device rd;
		std::default_random_engine generator(rd());

		JitRuntime rt;
		CodeHolder code;
		code.init(rt.environment());
		x86::Assembler a(&code);
		uint32_t random_add_val, rand_xor_val, rand_rot_val;
		switch (bit_of_value) {
		case 8: {
			random_add_val = rand() % 255 + 1;
			rand_xor_val = rand() % 255 + 1;
			rand_rot_val = rand() % 255 + 1;
			*(uint8_t*)(&instruction->raw_bytes.data()[instruction->zyinstr.raw.imm->offset]) = ~((_rotr8(*(uint8_t*)(&instruction->raw_bytes.data()[instruction->zyinstr.raw.imm->offset]), rand_rot_val) ^ rand_xor_val) - random_add_val);
			break;
		}
		case 16: {
			std::uniform_int_distribution<uint16_t>distribution(INT16_MAX / 2, INT16_MAX);
			random_add_val = distribution(generator);
			rand_xor_val = distribution(generator);
			rand_rot_val = distribution(generator);
			*(uint16_t*)(&instruction->raw_bytes.data()[instruction->zyinstr.raw.imm->offset]) = ~((_rotr16(*(uint16_t*)(&instruction->raw_bytes.data()[instruction->zyinstr.raw.imm->offset]), rand_rot_val) ^ rand_xor_val) - random_add_val);
			break;
		}
		case 32: {
			std::uniform_int_distribution<uint32_t>distribution(UINT32_MAX / 2, UINT32_MAX);
			random_add_val = distribution(generator);
			rand_xor_val = distribution(generator);
			rand_rot_val = distribution(generator);
			*(uint32_t*)(&instruction->raw_bytes.data()[instruction->zyinstr.raw.imm->offset]) = ~((_rotr(*(uint32_t*)(&instruction->raw_bytes.data()[instruction->zyinstr.raw.imm->offset]), rand_rot_val) ^ rand_xor_val) - random_add_val);
			break;
		}
		case 64: {
			std::uniform_int_distribution<uint32_t>distribution(INT32_MAX / 2, INT32_MAX);
			random_add_val = distribution(generator);
			rand_xor_val = distribution(generator);
			rand_rot_val = distribution(generator);
			*(uint64_t*)(&instruction->raw_bytes.data()[instruction->zyinstr.raw.imm->offset]) = ~((_rotr64(*(uint64_t*)(&instruction->raw_bytes.data()[instruction->zyinstr.raw.imm->offset]), rand_rot_val) ^ rand_xor_val) - random_add_val);
			break;
		}
		}

		a.pushf();
		a.not_(usingregister);
		a.add(usingregister, random_add_val);
		a.xor_(usingregister, rand_xor_val);
		a.rol(usingregister, rand_rot_val);
		a.popf();

		void* fn;
		auto err = rt.add(&fn, &code);

		auto jitinstructions = this->instructions_from_jit((uint8_t*)fn, code.codeSize());

		for (auto jit : jitinstructions) {
			instruction = function->instructions.insert(instruction + 1, jit);
		}

		rt.release(fn);

		return true;
		
	}
	return false;
}