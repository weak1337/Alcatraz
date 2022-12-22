#include "obfuscator.h"

#include <iostream>

ZydisFormatter formatter;
ZydisDecoder decoder;

int obfuscator::instruction_id;

obfuscator::obfuscator(pe64* pe) {

	this->pe = pe;

	if (!ZYAN_SUCCESS(ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_ADDRESS_WIDTH_64)))
		throw std::runtime_error("failed to init decoder");

	if(!ZYAN_SUCCESS(ZydisFormatterInit(&formatter, ZYDIS_FORMATTER_STYLE_INTEL)))
		throw std::runtime_error("failed to init formatter");

}

void obfuscator::create_functions(std::vector<pdbparser::sym_func>functions) {

	auto text_section = this->pe->get_section(".text");

	if (!text_section)
		throw std::runtime_error("couldn't find .text section");

	std::vector<uint32_t>visited_rvas;

	int function_iterator = 0;
	for (auto function : functions) {
		if (std::find(visited_rvas.begin(), visited_rvas.end(), function.offset) != visited_rvas.end())
			continue;
		if (function.size < 5)
			continue;

		ZydisDecodedInstruction zyinstruction{};

		auto address_to_analyze = this->pe->get_buffer()->data() + text_section->VirtualAddress + function.offset;
		uint32_t offset = 0;

		function_t new_function(function_iterator++,function.name, function.offset, function.size );

		while (ZYAN_SUCCESS(ZydisDecoderDecodeBuffer(&decoder, (void*)(address_to_analyze + offset), function.size - offset, &zyinstruction))) {

			instruction_t new_instruction{};
			new_instruction.runtime_address = (uint64_t)address_to_analyze + offset;
			new_instruction.load(function_iterator, zyinstruction, new_instruction.runtime_address);
			if (offset == 0)
				new_instruction.is_first_instruction = true;
			new_function.instructions.push_back(new_instruction);


			offset += new_instruction.zyinstr.length;;
		}

		visited_rvas.push_back(function.offset);
		this->functions.push_back(new_function);
	}
	
}

bool obfuscator::find_inst_at_dst(uint64_t dst, instruction_t** instptr, function_t** funcptr) {

	for (auto func = functions.begin(); func != functions.end(); ++func) {

		for (auto instruction = func->instructions.begin(); instruction != func->instructions.end(); ++instruction) {

			if (instruction->runtime_address == dst)
			{
				*instptr = &(*instruction);
				*funcptr = &(*func);
				return true;
			}
		}
	}
	return false;
}

void obfuscator::remove_jumptables() {
	for (auto func = functions.begin(); func != functions.end(); func++) {
		for (auto instruction = func->instructions.begin(); instruction != func->instructions.end(); instruction++) {
			if (instruction->has_relative && !instruction->isjmpcall && instruction->relative.size == 32) {

				auto relative_address = instruction->runtime_address + *(int32_t*)(&instruction->raw_bytes.data()[instruction->relative.offset]) + instruction->zyinstr.length;
				
				if (relative_address == (uint64_t)this->pe->get_buffer()->data()) {
					func = this->functions.erase(func);
					--func;
					break;
				}
			}
		}
	}
}

bool obfuscator::analyze_functions() {

	this->remove_jumptables();

	for (auto func = functions.begin(); func != functions.end(); func++) {
		for (auto instruction = func->instructions.begin(); instruction != func->instructions.end(); instruction++) {

			if (instruction->has_relative) {
				
				if (instruction->isjmpcall) {

					uint64_t absolute_address = 0;

					if (!ZYAN_SUCCESS(ZydisCalcAbsoluteAddress(&instruction->zyinstr, &instruction->zyinstr.operands[0], instruction->runtime_address, &absolute_address)))
						return false;
					
					obfuscator::instruction_t* instptr;
					obfuscator::function_t* funcptr;

					if (!this->find_inst_at_dst(absolute_address, &instptr, &funcptr)) {
						instruction->relative.target_inst_id = -1; //It doesnt jump to a func we relocate so we use absolute
						continue;
					}

					instruction->relative.target_inst_id = instptr->inst_id;
					instruction->relative.target_func_id = funcptr->func_id;
				}
				else {

					uint64_t original_data = instruction->runtime_address + instruction->zyinstr.length;;
					
					switch(instruction->relative.size){
					case 8:
						original_data += *(int8_t*)(&instruction->raw_bytes.data()[instruction->relative.offset]);
						break;
					case 16:
						original_data += *(int16_t*)(&instruction->raw_bytes.data()[instruction->relative.offset]);
						break;
					case 32:
						original_data += *(int32_t*)(&instruction->raw_bytes.data()[instruction->relative.offset]);
						break;
					}
					instruction->location_of_data = original_data;
				}
			}
		}
	}

	return true;
}

void obfuscator::relocate(PIMAGE_SECTION_HEADER new_section) {

	auto base = pe->get_buffer()->data();

	int used_memory = 0;

	for (auto func = functions.begin(); func != functions.end(); ++func) {

		uint32_t dst = new_section->VirtualAddress + used_memory;

		int instr_ctr = 0;

		for (auto instruction = func->instructions.begin(); instruction != func->instructions.end(); ++instruction) {

			instruction->relocated_address = (uint64_t)base + dst + instr_ctr;
			instr_ctr += instruction->zyinstr.length;
		}

		used_memory += instr_ctr;
	}

	this->total_size_used = used_memory;
}

bool obfuscator::find_instruction_by_id(int funcid, int instid, instruction_t* inst) {

	auto func = std::find_if(this->functions.begin(), this->functions.end(), [&](const obfuscator::function_t& func) {
		return func.func_id == funcid;
		});

	if (func == this->functions.end())
		return false;

	auto it = std::find_if(func->instructions.begin(), func->instructions.end(), [&](const obfuscator::instruction_t& inst) {
		return inst.inst_id == instid;
		});

	if (it != func->instructions.end())
	{
		*inst = *it;
		return true;

	}
	return false;
}

uint16_t rel8_to16(ZydisMnemonic mnemonic) {
	switch (mnemonic)
	{
	case ZYDIS_MNEMONIC_JNBE:
		return 0x870F;
	case ZYDIS_MNEMONIC_JB:
		return 0x820F;
	case ZYDIS_MNEMONIC_JBE:
		return 0x860F;
	case ZYDIS_MNEMONIC_JCXZ:
		return 0;
	case ZYDIS_MNEMONIC_JECXZ:
		return 0;
	case ZYDIS_MNEMONIC_JKNZD:
		return 0;
	case ZYDIS_MNEMONIC_JKZD:
		return 0;
	case ZYDIS_MNEMONIC_JL:
		return 0x8C0F;
	case ZYDIS_MNEMONIC_JLE:
		return 0x8E0F;
	case ZYDIS_MNEMONIC_JNB:
		return 0x830F;
	case ZYDIS_MNEMONIC_JNL:
		return 0x8D0F;
	case ZYDIS_MNEMONIC_JNLE:
		return 0x8F0F;
	case ZYDIS_MNEMONIC_JNO:
		return 0x810F;
	case ZYDIS_MNEMONIC_JNP:
		return 0x8B0F;
	case ZYDIS_MNEMONIC_JNS:
		return 0x890F;
	case ZYDIS_MNEMONIC_JNZ:
		return 0x850F;
	case ZYDIS_MNEMONIC_JO:
		return 0x800F;
	case ZYDIS_MNEMONIC_JP:
		return 0x8A0F;
	case ZYDIS_MNEMONIC_JRCXZ:
		return 0;
	case ZYDIS_MNEMONIC_JS:
		return 0x880F;
	case ZYDIS_MNEMONIC_JZ:
		return 0x840F;
	case ZYDIS_MNEMONIC_JMP:
		return 0xE990;
	default:
		break;
	}

	return 0;
}

bool obfuscator::fix_relative_jmps(function_t* func) {

	for (auto instruction = func->instructions.begin(); instruction != func->instructions.end(); instruction++) {
		if (instruction->isjmpcall && instruction->relative.target_inst_id != -1) {

			instruction_t inst;

			if (!this->find_instruction_by_id(instruction->relative.target_func_id, instruction->relative.target_inst_id, &inst)) {
				return false;
			}

			switch (instruction->relative.size) {
			case 8: {
				signed int distance = inst.relocated_address - instruction->relocated_address - instruction->zyinstr.length;
				if (distance > 127 || distance < -128) {

					if (instruction->zyinstr.mnemonic == ZYDIS_MNEMONIC_JMP) {


						instruction->raw_bytes.resize(5);
						*(uint8_t*)(instruction->raw_bytes.data()) = 0xE9;
						*(int32_t*)(&instruction->raw_bytes.data()[1]) = (int32_t)(inst.relocated_address - instruction->relocated_address - instruction->zyinstr.length);

						instruction->reload();

						for (auto instruction2 = instruction; instruction2 != func->instructions.end(); instruction2++) {
							instruction2->relocated_address += 3;
						}

						return this->fix_relative_jmps(func);

					}
					else {

						uint16_t new_opcode = rel8_to16(instruction->zyinstr.mnemonic);

						instruction->raw_bytes.resize(6);
						*(uint16_t*)(instruction->raw_bytes.data()) = new_opcode;
						*(int32_t*)(&instruction->raw_bytes.data()[2]) = (int32_t)(inst.relocated_address - instruction->relocated_address - instruction->zyinstr.length);

						for (auto instruction2 = instruction; instruction2 != func->instructions.end(); ++instruction2) {
							instruction2->relocated_address += 4;
						}

						return this->fix_relative_jmps(func);
					}

				}
				break;
			}

			case 16: {
				signed int distance = inst.relocated_address - instruction->relocated_address - instruction->zyinstr.length;
				if (distance > 32767 || distance < -32768)
				{
					//Unlikely, but:
					//Condition met? Jmp else Jmp (insert 2 jmps instead of converting conditional jump)
					return false;
				}
				break;
			}
			case 32: {
				signed int distance = inst.relocated_address - instruction->relocated_address - instruction->zyinstr.length;
				if (distance > 2147483647 || distance < -2147483648)
				{
					//Shouldn't be possible
					return false;
				}
				break;
			}
			default:
				return false;
			}

			

		}
	}
	return true;
}

bool obfuscator::convert_relative_jmps() {
	for (auto func = functions.begin(); func != functions.end(); ++func) {

		if (!this->fix_relative_jmps(&(*func)))
			return false;
	}
	return true;
}

bool obfuscator::apply_relocations(PIMAGE_SECTION_HEADER new_section) {

	this->relocate(new_section);

	for (auto func = functions.begin(); func != functions.end(); ++func) {
		for (auto instruction = func->instructions.begin(); instruction != func->instructions.end(); ++instruction) {

			if (instruction->has_relative) {

				if (instruction->isjmpcall) {

					if (instruction->relative.target_inst_id == -1) { //Points without relocation

						switch (instruction->relative.size) {
						case 8: {
							uint64_t dst = instruction->runtime_address + *(int8_t*)(&instruction->raw_bytes.data()[instruction->relative.offset]) + instruction->zyinstr.length;
							*(int8_t*)(&instruction->raw_bytes.data()[instruction->relative.offset]) = (int8_t)(dst - instruction->relocated_address - instruction->zyinstr.length);
							break;
						}
						case 16: {
							uint64_t dst = instruction->runtime_address + *(int16_t*)(&instruction->raw_bytes.data()[instruction->relative.offset]) + instruction->zyinstr.length;
							*(int16_t*)(&instruction->raw_bytes.data()[instruction->relative.offset]) = (int16_t)(dst - instruction->relocated_address - instruction->zyinstr.length);
							break;
						}
						case 32: {
							uint64_t dst = instruction->runtime_address + *(int32_t*)(&instruction->raw_bytes.data()[instruction->relative.offset]) + instruction->zyinstr.length;
							*(int32_t*)(&instruction->raw_bytes.data()[instruction->relative.offset]) = (int32_t)(dst - instruction->relocated_address - instruction->zyinstr.length);
							break;
						}
						default:
							return false;
						}

						memcpy((void*)instruction->relocated_address, instruction->raw_bytes.data(), instruction->zyinstr.length);
					}
					else {

						instruction_t inst;
						if (!this->find_instruction_by_id(instruction->relative.target_func_id, instruction->relative.target_inst_id, &inst)) {
							return false;
						}

						switch (instruction->relative.size) {
						case 8: {
							*(int8_t*)(&instruction->raw_bytes.data()[instruction->relative.offset]) = (int8_t)(inst.relocated_address - instruction->relocated_address - instruction->zyinstr.length);
							break;
						}
						case 16:
							*(int16_t*)(&instruction->raw_bytes.data()[instruction->relative.offset]) = (int16_t)(inst.relocated_address - instruction->relocated_address - instruction->zyinstr.length);
							break;
						case 32: {
							if (inst.is_first_instruction) //Jump to our stub in .text instead of relocated base
								*(int32_t*)(&instruction->raw_bytes.data()[instruction->relative.offset]) = (int32_t)(inst.runtime_address - instruction->relocated_address - instruction->zyinstr.length);
							else
								*(int32_t*)(&instruction->raw_bytes.data()[instruction->relative.offset]) = (int32_t)(inst.relocated_address - instruction->relocated_address - instruction->zyinstr.length);
							break;
						}
						default:
							return false;
						}

						memcpy((void*)instruction->relocated_address, instruction->raw_bytes.data(), instruction->zyinstr.length);
					}

				}
				else {

					uint64_t dst = instruction->location_of_data;
					switch (instruction->relative.size) {
					case 8: {
						*(int8_t*)(&instruction->raw_bytes.data()[instruction->relative.offset]) = (int8_t)(dst - instruction->relocated_address - instruction->zyinstr.length);
						break;
					}
					case 16: {
						*(int16_t*)(&instruction->raw_bytes.data()[instruction->relative.offset]) = (int16_t)(dst - instruction->relocated_address - instruction->zyinstr.length);
						break;
					}
					case 32: {
						*(int32_t*)(&instruction->raw_bytes.data()[instruction->relative.offset]) = (int32_t)(dst - instruction->relocated_address - instruction->zyinstr.length);
						break;
					}
					default:
						return false;
					}

					memcpy((void*)instruction->relocated_address, instruction->raw_bytes.data(), instruction->zyinstr.length);
				}

			}
			else {
				memcpy((void*)instruction->relocated_address, instruction->raw_bytes.data(), instruction->zyinstr.length);
			}

		}
	}

}

void obfuscator::compile(PIMAGE_SECTION_HEADER new_section) {

	const PIMAGE_SECTION_HEADER current_image_section = IMAGE_FIRST_SECTION(this->pe->get_nt());
	for (auto i = 0; i < this->pe->get_nt()->FileHeader.NumberOfSections; ++i) {
		current_image_section[i].PointerToRawData = current_image_section[i].VirtualAddress;
	}

	auto text_section = this->pe->get_section(".text");
	auto base = this->pe->get_buffer()->data();

	for (auto func = functions.begin(); func != functions.end(); ++func) {

		auto first_instruction = func->instructions.begin();

		const uint8_t jmp_shell[] = { 0xE9, 0x00, 0x00, 0x00, 0x00 };

		uint32_t src = text_section->VirtualAddress + func->offset;
		uint32_t dst = first_instruction->relocated_address - (uint64_t)pe->get_buffer()->data();


		*(int32_t*)&jmp_shell[1] = (signed int)(dst - src - sizeof(jmp_shell));

		for (int i = 0; i < func->size - 5; i++) {
			*(uint8_t*)((uint64_t)base + src + 5 + i) = rand() % 255 + 1;
		}

		memcpy((void*)(base + src), jmp_shell, sizeof(jmp_shell));
	}

}

void obfuscator::run(PIMAGE_SECTION_HEADER new_section) {

	if (!this->analyze_functions())
		throw std::runtime_error("couldn't analyze functions");

	this->relocate(new_section);

	if(!this->convert_relative_jmps())
		throw std::runtime_error("couldn't convert relative jmps");

	if (!this->apply_relocations(new_section))
		throw std::runtime_error("couldn't convert relative jmps");

	this->compile(new_section);
}

uint32_t obfuscator::get_added_size() {
	return this->total_size_used;
}

bool is_jmpcall(ZydisDecodedInstruction instr)
{
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
	case ZYDIS_MNEMONIC_JMP:
	case ZYDIS_MNEMONIC_CALL:
		return true;
	default:
		return false;
	}
	return false;
}

void obfuscator::instruction_t::load_relative_info() {

	if (!(this->zyinstr.attributes & ZYDIS_ATTRIB_IS_RELATIVE))
	{
		this->relative.offset = 0; this->relative.size = 0; this->has_relative = false;
		return;
	}

	this->has_relative = true;
	this->isjmpcall = is_jmpcall(this->zyinstr);

	ZydisInstructionSegments segs;
	ZydisGetInstructionSegments(&this->zyinstr, &segs);
	for (uint8_t idx = 0; idx < this->zyinstr.operand_count; ++idx)
	{
		auto& op = this->zyinstr.operands[idx];


		if (op.type == ZYDIS_OPERAND_TYPE_IMMEDIATE)
		{
			if (op.imm.is_relative)
			{
				for (uint8_t segIdx = 0; segIdx < segs.count; ++segIdx)
				{
					auto seg = segs.segments[segIdx];

					if (seg.type == ZYDIS_INSTR_SEGMENT_IMMEDIATE)
					{
						this->relative.offset = this->zyinstr.raw.imm->offset;
						this->relative.size = this->zyinstr.raw.imm->size;
						break;
					}
				}
			}
		}
		if (op.type == ZYDIS_OPERAND_TYPE_MEMORY)
		{
			if (op.mem.base == ZYDIS_REGISTER_RIP)
			{
				for (uint8_t segIdx = 0; segIdx < segs.count; ++segIdx)
				{
					auto seg = segs.segments[segIdx];

					if (seg.type == ZYDIS_INSTR_SEGMENT_DISPLACEMENT)
					{
						this->relative.offset = this->zyinstr.raw.disp.offset;
						this->relative.size = this->zyinstr.raw.disp.size;
						break;
					}
				}
			}
		}
	}
}

void obfuscator::instruction_t::load(int funcid, std::vector<uint8_t>raw_data) {

	this->inst_id = instruction_id++;
	ZydisDecoderDecodeBuffer(&decoder, raw_data.data(), raw_data.size(), &this->zyinstr);
	this->func_id = funcid;
	this->raw_bytes = raw_data;
	this->load_relative_info();
}
void obfuscator::instruction_t::load(int funcid,ZydisDecodedInstruction zyinstruction, uint64_t runtime_address) {
	this->inst_id = instruction_id++;
	this->zyinstr = zyinstruction;
	this->func_id = funcid;
	this->raw_bytes.resize(this->zyinstr.length); memcpy(this->raw_bytes.data(), (void*)runtime_address, this->zyinstr.length);
	this->load_relative_info();
}

void obfuscator::instruction_t::reload() {
	this->load_relative_info();
}

void obfuscator::instruction_t::print() {
	char buffer[256];
	ZydisFormatterFormatInstruction(&formatter, &this->zyinstr,
		buffer, sizeof(buffer), runtime_address);
	puts(buffer);
}