#include "../obfuscator.h"

#include <random>

bool is_jmp_conditional(ZydisDecodedInstruction instr) {
	switch (instr.mnemonic)
	{
	case ZYDIS_MNEMONIC_JNBE:
	case ZYDIS_MNEMONIC_JB:
	case ZYDIS_MNEMONIC_JBE:
	case ZYDIS_MNEMONIC_JCXZ:
	case ZYDIS_MNEMONIC_JECXZ:
	case ZYDIS_MNEMONIC_JKNZD:
	case ZYDIS_MNEMONIC_JKZD:
	case ZYDIS_MNEMONIC_JL:
	case ZYDIS_MNEMONIC_JLE:
	case ZYDIS_MNEMONIC_JNB:
	case ZYDIS_MNEMONIC_JNL:
	case ZYDIS_MNEMONIC_JNLE:
	case ZYDIS_MNEMONIC_JNO:
	case ZYDIS_MNEMONIC_JNP:
	case ZYDIS_MNEMONIC_JNS:
	case ZYDIS_MNEMONIC_JNZ:
	case ZYDIS_MNEMONIC_JO:
	case ZYDIS_MNEMONIC_JP:
	case ZYDIS_MNEMONIC_JRCXZ:
	case ZYDIS_MNEMONIC_JS:
	case ZYDIS_MNEMONIC_JZ:
		return true;
	default:
		return false;
	}
	return false;
}



bool obfuscator::flatten_control_flow(std::vector<obfuscator::function_t>::iterator& func){

	struct block_t {
		int block_id;
		std::vector < obfuscator::instruction_t>instructions;

		int next_block;
		int dst_block = -1;

	};

	std::vector<block_t>blocks;
	std::vector<int>block_starts;
	block_t block;
	int block_iterator = 0;

	//In the first round we mark all jmp destinations that land back inside this func
	for (auto instruction = func->instructions.begin(); instruction != func->instructions.end(); instruction++) {

		if (is_jmp_conditional(instruction->zyinstr) || (instruction->zyinstr.mnemonic == ZYDIS_MNEMONIC_JMP && instruction->zyinstr.raw.imm->size == 8)) {

			if (instruction->relative.target_func_id == func->func_id) {
				block_starts.push_back(instruction->relative.target_inst_id);
			}
		}
	}

	//Now we create our blocks
	for (auto instruction = func->instructions.begin(); instruction != func->instructions.end(); instruction++) {

		block.instructions.push_back(*instruction);
		auto next_instruction = instruction + 1;

		if (next_instruction != func->instructions.end()) {

			if (std::find(block_starts.begin(), block_starts.end(), next_instruction->inst_id) != block_starts.end()) {
				block.block_id = block_iterator++;
				blocks.push_back(block);
				block.instructions.clear();
				continue;
			}
		}
		else{
			block.block_id = block_iterator++;
			blocks.push_back(block);
			block.instructions.clear();
			continue;
		}
		
		if (instruction->zyinstr.mnemonic == ZYDIS_MNEMONIC_RET || (instruction->isjmpcall && instruction->zyinstr.mnemonic != ZYDIS_MNEMONIC_CALL))
		{
			block.block_id = block_iterator++;
			blocks.push_back(block);
			block.instructions.clear();
		}
	}
	

	//Time to link them together
	for (auto current_block = blocks.begin(); current_block != blocks.end(); current_block++) {
		
		auto last_instruction = current_block->instructions.end() - 1;
		current_block->next_block = current_block->block_id + 1;

	
		if (last_instruction->isjmpcall && is_jmp_conditional(last_instruction->zyinstr)) {	
			for (auto current_block2 = blocks.begin(); current_block2 != blocks.end(); current_block2++) {
				
				auto first_instruction = current_block2->instructions.begin();
				if (first_instruction->inst_id == last_instruction->relative.target_inst_id) {
					current_block->dst_block = current_block2->block_id;
					break;
				}
			}
		}
	}

	int first_inst_id = func->instructions.begin()->inst_id;
	int new_id = this->instruction_id++;
	func->instructions.begin()->inst_id = new_id;
	func->instructions.begin()->is_first_instruction = false;


	//Lets shuffle so they cant just strip our stuff
	auto rng = std::default_random_engine{};
	std::shuffle(blocks.begin(), blocks.end(), rng);

	//Generate our control structure
	instruction_t push_rax{}; push_rax.load(func->func_id, { 0x50 });
	push_rax.inst_id = first_inst_id;
	push_rax.is_first_instruction = false;
	auto it = func->instructions.insert(func->instructions.begin(), push_rax);
	instruction_t push_f{}; push_f.load(func->func_id, { 0x66, 0x9C });
	it = func->instructions.insert(it + 1, push_f);
	instruction_t mov_eax_0{}; mov_eax_0.load(func->func_id, { 0xB8, 0x00,0x00,0x00,0x00 });
	it = func->instructions.insert(it + 1, mov_eax_0);

	for (auto current_block = blocks.begin(); current_block != blocks.end(); current_block++) {

		instruction_t cmp_eax{}; cmp_eax.load(func->func_id, { 0x3D, 0x00, 0x00,0x00,0x00 });
		*(uint32_t*)&cmp_eax.raw_bytes.data()[1] = current_block->block_id;
		
		instruction_t jne{}; jne.load(func->func_id, { 0x75, 0x08 });

		instruction_t pop_f{}; pop_f.load(func->func_id, { 0x66, 0x9D });

		instruction_t pop_rax{}; pop_rax.load(func->func_id, { 0x58 });
		
		instruction_t jmp{}; jmp.load(func->func_id, { 0xE9,0x00,0x00,0x00,0x00 });
		jmp.relative.target_inst_id = current_block->block_id == 0 ? new_id : current_block->instructions.begin()->inst_id;
		jmp.relative.target_func_id = func->func_id;
		
		it = func->instructions.insert(it + 1, { cmp_eax , jne, pop_f, pop_rax, jmp });
		it = it + 4;
	}

	//Fix added jz relatives
	for (auto inst = func->instructions.begin(); inst != it + 1; inst++) {

		if (inst->zyinstr.mnemonic == ZYDIS_MNEMONIC_JNZ) {
			auto dst = inst + 4;

			inst->relative.target_func_id = func->func_id;
			inst->relative.target_inst_id = dst->inst_id;
		}
	}

	for (auto current_block = blocks.begin(); current_block != blocks.end() - 1; current_block++) {

		int instructions_index = func->inst_id_index[(current_block->instructions.end() - 1)->inst_id];
		auto last_instruction = func->instructions.begin() + instructions_index;

		auto next_block = std::find_if(blocks.begin(), blocks.end(), [&](const block_t block) {return block.block_id == current_block->next_block; });
		if (next_block == blocks.end()) continue;

		if (is_jmp_conditional(last_instruction->zyinstr) && current_block->dst_block != -1) {

			auto dst_block = std::find_if(blocks.begin(), blocks.end(), [&](const block_t block) {return block.block_id == current_block->dst_block; });

			//This happens if condition is not met
			{
				instruction_t push_rax{}; push_rax.load(func->func_id, { 0x50 });

				instruction_t push_f{}; push_f.load(func->func_id, { 0x66, 0x9C });

				instruction_t mov_eax{}; mov_eax.load(func->func_id, { 0xB8, 0x00,0x00,0x00,0x00 });
				*(uint32_t*)(&mov_eax.raw_bytes.data()[1]) = next_block->block_id;

				instruction_t jmp{}; jmp.load(func->func_id, { 0xE9, 0x00,0x00,0x00,0x00 });
				jmp.relative.target_func_id = func->func_id;
				jmp.relative.target_inst_id = (func->instructions.begin() + 3)->inst_id;

				last_instruction = func->instructions.insert(last_instruction + 1, { push_rax , push_f, mov_eax, jmp });
				last_instruction = last_instruction + 3;
			}

			//This happens if condition is met
			{

				instruction_t push_rax{}; push_rax.load(func->func_id, { 0x50 });

				instruction_t push_f{}; push_f.load(func->func_id, { 0x66, 0x9C });

				instruction_t mov_eax{}; mov_eax.load(func->func_id, { 0xB8, 0x00,0x00,0x00,0x00 });
				*(uint32_t*)(&mov_eax.raw_bytes.data()[1]) = dst_block->block_id;

				instruction_t jmp{}; jmp.load(func->func_id, { 0xE9, 0x00,0x00,0x00,0x00 });
				jmp.relative.target_func_id = func->func_id;
				jmp.relative.target_inst_id = (func->instructions.begin() + 3)->inst_id;

				last_instruction = func->instructions.insert(last_instruction + 1, { push_rax , push_f, mov_eax, jmp });
				last_instruction = last_instruction + 3;
			}

			//Lets set the destination of our conditinal jump to our second option
			last_instruction = last_instruction - 8;
			last_instruction->relative.target_inst_id = (last_instruction + 5)->inst_id;

		}
		else {

			instruction_t push_rax{}; push_rax.load(func->func_id, { 0x50 });

			instruction_t push_f{}; push_f.load(func->func_id, { 0x66, 0x9C });

			instruction_t mov_eax{}; mov_eax.load(func->func_id, { 0xB8, 0x00,0x00,0x00,0x00 });
			*(uint32_t*)(&mov_eax.raw_bytes.data()[1]) = next_block->block_id;

			instruction_t jmp{}; jmp.load(func->func_id, { 0xE9, 0x00,0x00,0x00,0x00 });
			jmp.relative.target_func_id = func->func_id;
			jmp.relative.target_inst_id = (func->instructions.begin() + 3)->inst_id;

			auto it = func->instructions.insert(last_instruction + 1, { push_rax , push_f, mov_eax, jmp });
			it = it + 3;
		}
	}
	
	return true;
}
