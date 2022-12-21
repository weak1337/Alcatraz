#include "pe.h"

#include <filesystem>
#include <fstream>


pe64::pe64(std::string binary_path) {

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
		throw std::runtime_error("Alcatraz doesn't support 32bit pe files!");

	this->buffer.resize(nt->OptionalHeader.SizeOfImage);
	this->buffer.clear();

	auto first_section = IMAGE_FIRST_SECTION(nt);

	memcpy(this->buffer.data(), temp_buffer.data(), 0x1000);
	for (int i = 0; i < nt->FileHeader.NumberOfSections; i++) {	

		auto curr_section = &first_section[i];
		
		memcpy(this->buffer.data() + curr_section->VirtualAddress, temp_buffer.data() + curr_section->PointerToRawData, curr_section->SizeOfRawData);

	}
}

std::vector<uint8_t>* pe64::get_buffer() {
	return &this->buffer;
}

PIMAGE_NT_HEADERS pe64::get_nt() {
	return reinterpret_cast<PIMAGE_NT_HEADERS>(this->buffer.data() + ((PIMAGE_DOS_HEADER)this->buffer.data())->e_lfanew);
}