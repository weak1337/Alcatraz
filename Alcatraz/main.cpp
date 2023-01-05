#include "pe/pe.h"
#include "pdbparser/pdbparser.h"
#include "obfuscator/obfuscator.h"

#include <iostream>
#include <filesystem>

int main(int args, char* argv[]) {

	if (args != 2) {
		printf("Usage: [exe_path]\n");
		return 0;
	}


	std::string binary_path = argv[1];
	const clock_t begin_time = clock();

	try {
		srand(time(NULL));

		pe64 pe(binary_path);
		pdbparser pdb(&pe);
	
		auto functions = pdb.parse_functions();
		std::cout << "Successfully parsed " << functions.size() << " function(s)" << std::endl;

		auto new_section = pe.create_section(".0Dev", 10000000, IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ | IMAGE_SCN_CNT_CODE);

		obfuscator obf(&pe);
		obf.create_functions(functions);
		obf.run(new_section, true);
	
		auto extension = std::filesystem::path(binary_path).extension();
		pe.save_to_disk(std::filesystem::path(binary_path).replace_extension().string() + ".obf" + extension.string(), new_section, obf.get_added_size());
			

	}
	catch (std::runtime_error e)
	{
		std::cout << "Runtime error: " << e.what() << std::endl;
	}

	auto t_end = std::chrono::high_resolution_clock::now();
	std::cout << "Finished in " << float(clock() - begin_time) / CLOCKS_PER_SEC << " seconds" << std::endl;
	return getchar();
}