#include "pe/pe.h"
#include "pdbparser/pdbparser.h"
#include "obfuscator/obfuscator.h"

#include <iostream>
#include <filesystem>

int main() {
	std::string binary_path = 
	//	"C:\\Users\\bsodcloud\\Desktop\\Klar.gg\\Hello\\x64\\Release\\hello.exe";
		"C:\\Users\\bsodcloud\\Desktop\\Klar.gg\\KlarNetworking - Kopie\\x64\\Release\\Klarclient.exe";

	try {
		srand(time(NULL));

		pe64 pe(binary_path);
		pdbparser pdb(&pe);
		auto functions = pdb.parse_functions();
		std::cout << "Successfully parsed " << functions.size() << " function(s)" << std::endl;

		auto new_section = pe.create_section(".0Dev", 10000000, IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ | IMAGE_SCN_CNT_CODE);

		obfuscator obf(&pe);
		obf.create_functions(functions);
		obf.run(new_section);
	
		auto extension = std::filesystem::path(binary_path).extension();
		pe.save_to_disk(std::filesystem::path(binary_path).replace_extension().u8string() + ".obf" + extension.u8string(), new_section, obf.get_added_size());
			
	}
	catch (std::runtime_error e)
	{
		std::cout << "Runtime error: " << e.what();
	}

	std::cout << "Finished" << std::endl;
	return getchar();
}