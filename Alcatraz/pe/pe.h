#pragma once
#include <string>
#include <vector>
#include <Windows.h>

class pe64 {
private:

	std::vector<uint8_t>buffer;

public:

	pe64(std::string binary_path);

	std::vector<uint8_t>* get_buffer();

	PIMAGE_NT_HEADERS get_nt();

};