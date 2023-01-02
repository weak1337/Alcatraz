#pragma once
#include <string>
#include <vector>
#include <Windows.h>

class pe64 {
private:

	std::vector<uint8_t>buffer;
	std::vector<uint8_t>buffer_not_relocated;
	std::string path;

public:

	pe64(std::string binary_path);

	uint32_t align(uint32_t address, uint32_t alignment);

	std::vector<uint8_t>* get_buffer();

	std::vector<uint8_t>* get_buffer_not_relocated();

	PIMAGE_NT_HEADERS get_nt();

	PIMAGE_SECTION_HEADER get_section(std::string sectionname);

	PIMAGE_SECTION_HEADER create_section(std::string name, uint32_t size, uint32_t characteristic);

	void save_to_disk(std::string path, PIMAGE_SECTION_HEADER new_section, uint32_t total_size);

	std::string get_path();
};