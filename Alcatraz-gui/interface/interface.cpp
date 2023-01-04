#include "interface.h"


#include <Windows.h>
#include <time.h>
#include <filesystem>


std::string binary_path;
std::vector<pdbparser::sym_func> inter::load_context(std::string path) {

	//If user loads new image

	srand(time(NULL));
	binary_path = path;
	pe64 pe(path);
	pdbparser pdb(&pe);

	return pdb.parse_functions();
}

void inter::run_obfuscator(std::vector<pdbparser::sym_func> funcs, bool obfuscate_entry_point) {

	pe64 pe(binary_path);
	auto extension = std::filesystem::path(binary_path).extension();

	std::remove((std::filesystem::path(binary_path).replace_extension().string() + ".obf" + extension.string()).c_str());
	auto new_section = pe.create_section(".0Dev", 10000000, IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ | IMAGE_SCN_CNT_CODE);

	obfuscator obf(&pe);
	obf.create_functions(funcs);
	obf.run(new_section, obfuscate_entry_point);


	pe.save_to_disk(std::filesystem::path(binary_path).replace_extension().string() + ".obf" + extension.string(), new_section, obf.get_added_size());

}