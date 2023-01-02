#include "pe.h"

#include <filesystem>
#include <fstream>


pe64::pe64(std::string binary_path) {

	this->path = binary_path;

	if (!std::filesystem::exists(binary_path))
		throw std::runtime_error("binary path doesn't exist!");

	std::ifstream file_stream(binary_path, std::ios::binary);
	if(!file_stream)
		throw std::runtime_error("couldn't open input binary!");

	this->buffer.assign((std::istreambuf_iterator<char>(file_stream)),
		std::istreambuf_iterator<char>());

	file_stream.close();

	std::vector<uint8_t>temp_buffer = buffer;

	PIMAGE_DOS_HEADER dos =
		reinterpret_cast<PIMAGE_DOS_HEADER>(temp_buffer.data());

	if(dos->e_magic != 'ZM')
		throw std::runtime_error("input binary isn't a valid pe file!");

	PIMAGE_NT_HEADERS nt =
		reinterpret_cast<PIMAGE_NT_HEADERS>(temp_buffer.data() + dos->e_lfanew);

	if(nt->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64)
		throw std::runtime_error("Alcatraz doesn't support 32bit binaries!");

	this->buffer.resize(nt->OptionalHeader.SizeOfImage);

	memset(this->buffer.data(), 0, nt->OptionalHeader.SizeOfImage);

	auto first_section = IMAGE_FIRST_SECTION(nt);

	memcpy(this->buffer.data(), temp_buffer.data(), 0x1000);
	for (int i = 0; i < nt->FileHeader.NumberOfSections; i++) {	

		auto curr_section = &first_section[i];
		
		memcpy(this->buffer.data() + curr_section->VirtualAddress, temp_buffer.data() + curr_section->PointerToRawData, curr_section->SizeOfRawData);

	}
	this->buffer_not_relocated = temp_buffer;
}

std::vector<uint8_t>* pe64::get_buffer() {
	return &this->buffer;
}

std::vector<uint8_t>* pe64::get_buffer_not_relocated() {
	return &this->buffer_not_relocated;
}

PIMAGE_NT_HEADERS pe64::get_nt() {
	return reinterpret_cast<PIMAGE_NT_HEADERS>(this->buffer.data() + ((PIMAGE_DOS_HEADER)this->buffer.data())->e_lfanew);
}

PIMAGE_SECTION_HEADER pe64::get_section(std::string sectionname) {

	auto first_section = IMAGE_FIRST_SECTION(this->get_nt());

	for (int i = 0; i < this->get_nt()->FileHeader.NumberOfSections; i++) {

		auto curr_section = &first_section[i];
		if (!_stricmp((char*)curr_section->Name, sectionname.c_str()))
			return curr_section;
	}

	return nullptr;
}

uint32_t pe64::align(uint32_t address, uint32_t alignment) {
	address += (alignment - (address % alignment));
	return address;
}

PIMAGE_SECTION_HEADER pe64::create_section(std::string name, uint32_t size, uint32_t characteristic) {

	if (name.length() > IMAGE_SIZEOF_SHORT_NAME)
		throw std::runtime_error("section name can't be longer than 8 characters!");
	PIMAGE_FILE_HEADER file_header = &this->get_nt()->FileHeader;
	PIMAGE_OPTIONAL_HEADER optional_header = &this->get_nt()->OptionalHeader;
	PIMAGE_SECTION_HEADER section_header = (PIMAGE_SECTION_HEADER)IMAGE_FIRST_SECTION(this->get_nt());
	PIMAGE_SECTION_HEADER last_section = &section_header[file_header->NumberOfSections - 1];
	PIMAGE_SECTION_HEADER new_section_header = nullptr;
	new_section_header = (PIMAGE_SECTION_HEADER)((PUCHAR)(&last_section->Characteristics) + 4);
	memcpy(new_section_header->Name, name.c_str(), name.length());
	new_section_header->Misc.VirtualSize = align(size + sizeof(uint32_t) + 1, optional_header->SectionAlignment);
	new_section_header->VirtualAddress = align(last_section->VirtualAddress + last_section->Misc.VirtualSize, optional_header->SectionAlignment);
	new_section_header->SizeOfRawData = align(size + sizeof(uint32_t) + 1, optional_header->FileAlignment);
	new_section_header->PointerToRawData = align(last_section->PointerToRawData + last_section->SizeOfRawData, optional_header->FileAlignment);
	new_section_header->Characteristics = characteristic;
	new_section_header->PointerToRelocations = 0x0;
	new_section_header->PointerToLinenumbers = 0x0;
	new_section_header->NumberOfRelocations = 0x0;
	new_section_header->NumberOfLinenumbers = 0x0;

	file_header->NumberOfSections += 1;
	uint32_t old_size = optional_header->SizeOfImage;
	optional_header->SizeOfImage = align(optional_header->SizeOfImage + size + sizeof(uint32_t) + 1 + sizeof(IMAGE_SECTION_HEADER), optional_header->SectionAlignment);
	optional_header->SizeOfHeaders = align(optional_header->SizeOfHeaders + sizeof(IMAGE_SECTION_HEADER), optional_header->FileAlignment);

	std::vector<uint8_t>new_buffer;
	new_buffer.resize(optional_header->SizeOfImage);
	memset(new_buffer.data(), 0, optional_header->SizeOfImage);
	memcpy(new_buffer.data(), this->buffer.data(), old_size);
	this->buffer = new_buffer;

	return this->get_section(name);
}

void pe64::save_to_disk(std::string path, PIMAGE_SECTION_HEADER new_section, uint32_t total_size) {


	uint32_t size = this->align(total_size, this->get_nt()->OptionalHeader.SectionAlignment);

	uint32_t original_size = new_section->Misc.VirtualSize;
	new_section->SizeOfRawData = size;
	new_section->Misc.VirtualSize = size;
	this->get_nt()->OptionalHeader.SizeOfImage -= (original_size - size);

	std::ofstream file_stream(path.c_str(), std::ios_base::out | std::ios_base::binary);
	if (!file_stream)
		throw std::runtime_error("couldn't open output binary!");

	if (!file_stream.write((char*)this->buffer.data(), this->get_nt()->OptionalHeader.SizeOfImage)) {
		file_stream.close();
		throw std::runtime_error("couldn't write output binary!");
	}

	file_stream.close();
}

std::string pe64::get_path() {
	return this->path;
}