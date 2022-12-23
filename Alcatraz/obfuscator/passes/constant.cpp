#include "../obfuscator.h"

#include <unordered_map>
#include <asmjit/asmjit.h>
#include <random>

using namespace asmjit;

std::unordered_map<ZydisRegister_, x86::Gp>lookupmap = {
	//8bit
	{ZYDIS_REGISTER_AL, x86::al},
	{ZYDIS_REGISTER_CL, x86::cl},
	{ZYDIS_REGISTER_DL, x86::dl},
	{ZYDIS_REGISTER_BL, x86::bl},
	{ZYDIS_REGISTER_AH, x86::ah},
	{ZYDIS_REGISTER_CH, x86::ch},
	{ZYDIS_REGISTER_DH, x86::dh},
	{ZYDIS_REGISTER_BH, x86::bh},
	{ZYDIS_REGISTER_SPL, x86::spl},
	{ZYDIS_REGISTER_BPL, x86::bpl},
	{ZYDIS_REGISTER_SIL, x86::sil},
	{ZYDIS_REGISTER_DIL, x86::dil},
	{ZYDIS_REGISTER_R8B, x86::r8b},
	{ZYDIS_REGISTER_R9B, x86::r9b},
	{ZYDIS_REGISTER_R10B, x86::r10b},
	{ZYDIS_REGISTER_R11B, x86::r11b},
	{ZYDIS_REGISTER_R12B, x86::r12b},
	{ZYDIS_REGISTER_R13B, x86::r13b},
	{ZYDIS_REGISTER_R14B, x86::r14b},
	{ZYDIS_REGISTER_R15B, x86::r15b},


	//16bit
	{ZYDIS_REGISTER_AX, x86::ax},
	{ZYDIS_REGISTER_CX, x86::cx},
	{ZYDIS_REGISTER_DX, x86::dx},
	{ZYDIS_REGISTER_BX, x86::bx},
	{ZYDIS_REGISTER_SP, x86::sp},
	{ZYDIS_REGISTER_BP, x86::bp},
	{ZYDIS_REGISTER_SI, x86::si},
	{ZYDIS_REGISTER_DI, x86::di},
	{ZYDIS_REGISTER_R8W, x86::r8w},
	{ZYDIS_REGISTER_R9W, x86::r9w},
	{ZYDIS_REGISTER_R10W, x86::r10w},
	{ZYDIS_REGISTER_R11W, x86::r11w},
	{ZYDIS_REGISTER_R12W, x86::r12w},
	{ZYDIS_REGISTER_R13W, x86::r13w},
	{ZYDIS_REGISTER_R14W, x86::r14w},
	{ZYDIS_REGISTER_R15W, x86::r15w},

	//32bit

	{ZYDIS_REGISTER_EAX, x86::eax},
	{ZYDIS_REGISTER_ECX, x86::ecx},
	{ZYDIS_REGISTER_EDX, x86::edx},
	{ZYDIS_REGISTER_EBX, x86::ebx},
	{ZYDIS_REGISTER_ESP, x86::esp},
	{ZYDIS_REGISTER_EBP, x86::ebp},
	{ZYDIS_REGISTER_ESI, x86::esi},
	{ZYDIS_REGISTER_EDI, x86::edi},
	{ZYDIS_REGISTER_R8D, x86::r8d},
	{ZYDIS_REGISTER_R9D, x86::r9d},
	{ZYDIS_REGISTER_R10D, x86::r10d},
	{ZYDIS_REGISTER_R11D, x86::r11d},
	{ZYDIS_REGISTER_R12D, x86::r12d},
	{ZYDIS_REGISTER_R13D, x86::r13d},
	{ZYDIS_REGISTER_R14D, x86::r14d},
	{ZYDIS_REGISTER_R15D, x86::r15d},

	//64bit

	{ZYDIS_REGISTER_RAX, x86::rax},
	{ZYDIS_REGISTER_RCX, x86::rcx},
	{ZYDIS_REGISTER_RDX, x86::rdx},
	{ZYDIS_REGISTER_RBX, x86::rbx},
	{ZYDIS_REGISTER_RSP, x86::rsp},
	{ZYDIS_REGISTER_RBP, x86::rbp},
	{ZYDIS_REGISTER_RSI, x86::rsi},
	{ZYDIS_REGISTER_RDI, x86::rdi},
	{ZYDIS_REGISTER_R8, x86::r8},
	{ZYDIS_REGISTER_R9, x86::r9},
	{ZYDIS_REGISTER_R10, x86::r10},
	{ZYDIS_REGISTER_R11, x86::r11},
	{ZYDIS_REGISTER_R12, x86::r12},
	{ZYDIS_REGISTER_R13, x86::r13},
	{ZYDIS_REGISTER_R14, x86::r14},
	{ZYDIS_REGISTER_R15, x86::r15}


};

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



		//a.nop();
		a.pushf();
		a.not_(usingregister);
		a.add(usingregister, random_add_val);
		a.xor_(usingregister, rand_xor_val);
		a.rol(usingregister, rand_rot_val);
		a.popf();



		void* fn;
		auto err = rt.add(&fn, &code);

		auto jitinstructions = this->instructions_from_jit((uint8_t*)fn, code.codeSize());

		/*
		int orig_inst_id = jitinstructions.at(0).inst_id;
		jitinstructions.at(0).inst_id = instruction->inst_id;
		jitinstructions.at(0).func_id = instruction->func_id;
		jitinstructions.at(0).is_first_instruction = instruction->is_first_instruction;
		jitinstructions.at(0).runtime_address = instruction->runtime_address;

		instruction->inst_id = orig_inst_id; //Swap instruction ids
		instruction->is_first_instruction = false;
		*/
		instruction = function->instructions.insert(instruction + 1, jitinstructions.at(0));
		instruction = function->instructions.insert(instruction + 1, jitinstructions.at(1));
		instruction = function->instructions.insert(instruction + 1, jitinstructions.at(2));
		instruction = function->instructions.insert(instruction + 1, jitinstructions.at(3));
		instruction = function->instructions.insert(instruction + 1, jitinstructions.at(4));
		instruction = function->instructions.insert(instruction + 1, jitinstructions.at(5));

		rt.release(fn);

		return true;
		
	}
	return false;
}