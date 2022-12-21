#include "pe/pe.h"
#include "pdbparser/pdbparser.h"
#include <iostream>

int main() {
	std::string binary_path = 
		"C:\\Users\\bsodcloud\\Desktop\\Klar.gg\\Hello\\x64\\Release\\hello.exe";

	try {

		pe64 pe(binary_path);
		pdbparser pdb(&pe);

		auto functions = pdb.parse_functions();
		
	}
	catch (std::runtime_error e)
	{
		std::cout << "Runtime error: " << e.what();
	}


	return getchar();
}