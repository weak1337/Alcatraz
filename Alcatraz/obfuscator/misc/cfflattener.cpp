#include "../obfuscator.h"


bool obfuscator::flatten_control_flow(std::vector<obfuscator::function_t>::iterator& func){

	struct block {
		int block_id;
		std::vector < obfuscator::instruction_t>instructions;

		int next_block;
		int dst_block = -1;

	};

	std::vector<block>blocks;
	std::vector<int>block_starts;
	block block;
	int block_iterator = 0;

	//In the first round we mark all jmp destinations that land back inside this func
	for (auto instruction = func->instructions.begin(); instruction != func->instructions.end(); instruction++) {

		if (instruction->isjmpcall && instruction->relative.size != 32) {
			
			if(instruction->relative.target_func_id == func->func_id){
				block_starts.push_back(instruction->relative.target_inst_id);
			}
		}

	}

	//Now we create our blocks
	for (auto instruction = func->instructions.begin(); instruction != func->instructions.end(); instruction++) {
		block.instructions.push_back(*instruction);

		if (instruction != func->instructions.end() - 1) {

			auto next = instruction + 1;
			if (std::find(block_starts.begin(), block_starts.end(), next->inst_id) != block_starts.end()) {
				block.block_id = block_iterator++;
				block.next_block = block.block_id + 1;
				blocks.push_back(block);
				block.instructions.clear();
				continue;
			}

		}

		if (
			instruction->zyinstr.mnemonic == ZYDIS_MNEMONIC_RET 
			|| (instruction->isjmpcall && instruction->relative.size != 32) 
			|| instruction == func->instructions.end() - 1
			)
		{
			block.block_id = block_iterator++;
			block.next_block = block.block_id + 1;
			blocks.push_back(block);
			block.instructions.clear();
		}
	}
	
	//Time to link them together
	for (auto current_block = blocks.begin(); current_block != blocks.end(); current_block++) {
		
		auto last_instruction = current_block->instructions.end() - 1;

		if (last_instruction->isjmpcall && last_instruction->relative.target_func_id == func->func_id) {

			for (auto current_block2 = blocks.begin(); current_block2 != blocks.end(); current_block2++) {

				for (auto instruction : current_block2->instructions) {

					if (last_instruction->relative.target_inst_id == instruction.inst_id) {
						current_block->dst_block = current_block2->block_id;
					}

				}

			}

		}
	
	}

	int first_inst_id = func->instructions.begin()->inst_id;
	int new_id = this->instruction_id++;
	func->instructions.begin()->inst_id = new_id;
	func->instructions.begin()->is_first_instruction = false;
	//Generate our control structure

	instruction_t push_rax{}; push_rax.load(func->func_id, { 0x50 });
	push_rax.inst_id = first_inst_id;
	push_rax.is_first_instruction = true;
	auto it = func->instructions.insert(func->instructions.begin(), push_rax);
	instruction_t push_f{}; push_f.load(func->func_id, { 0x66, 0x9C });
	it = func->instructions.insert(it + 1, push_f);
	instruction_t mov_eax_0{}; mov_eax_0.load(func->func_id, { 0xB8, 0x01,0x00,0x00,0x00 });
	it = func->instructions.insert(it + 1, mov_eax_0);

	for (auto current_block : blocks) {

		instruction_t cmp_eax{}; cmp_eax.load(func->func_id, { 0x3D, 0x00, 0x00,0x00,0x00 });
		*(uint32_t*)&cmp_eax.raw_bytes.data()[1] = current_block.block_id;
		

		instruction_t jne{}; jne.load(func->func_id, { 0x75, 0x08 });
		jne.relative.target_inst_id = jne.inst_id + 4;
		jne.relative.target_func_id = func->func_id;


		instruction_t pop_f{}; pop_f.load(func->func_id, { 0x66, 0x9D });
		

		instruction_t pop_rax{}; pop_rax.load(func->func_id, { 0x58 });
		

		instruction_t jmp{}; jmp.load(func->func_id, { 0xE9,0x00,0x00,0x00,0x00 });
		jmp.relative.target_inst_id = current_block.block_id == 0 ? new_id : current_block.instructions.begin()->inst_id;
		jmp.relative.target_func_id = func->func_id;
		

		it = func->instructions.insert(it + 1, cmp_eax);
		it = func->instructions.insert(it + 1, jne);
		it = func->instructions.insert(it + 1, pop_f);
		it = func->instructions.insert(it + 1, pop_rax);
		it = func->instructions.insert(it+1, jmp);



		printf("=========== BLOCK %i ==============\n", current_block.block_id);
		
		for (auto inst : current_block.instructions) {
			inst.print();
		}
		printf("POSSIBLE: %i %i\n", current_block.next_block, current_block.dst_block);

	}

	for (auto current_block : blocks) {
		for (auto inst : current_block.instructions) {
			//func->instructions.push_back(inst);
		}
	}

}
