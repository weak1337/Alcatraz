#include "gui.h"
#include "imgui/imgui.h"
#include "imgui/imgui_impl_win32.h"
#include "imgui/imgui_impl_dx11.h"

#include "../interface/interface.h"

#include <d3d11.h>
#include <tchar.h>
#include <filesystem>

std::string path = "";

int panel = 0;
int selected_func = 0;
char func_name[1024];

std::vector<pdbparser::sym_func>funcs;
std::vector<pdbparser::sym_func>funcs_to_obfuscate;
std::vector<std::string>logs;
bool obf_entry_point;

void gui::render_interface() {
	ImGuiStyle& style = ImGui::GetStyle();
	style.WindowPadding = ImVec2(0, 0);
	
	ImGui::SetNextWindowSize(ImVec2(1280, 800));
	ImGui::SetNextWindowPos(ImVec2(0, 0));
	ImGui::Begin("Alcaztaz",0, ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_MenuBar | ImGuiWindowFlags_NoScrollWithMouse);

	if (ImGui::BeginMenuBar()) {

		if (ImGui::BeginMenu("File")) {

			if (ImGui::MenuItem("Open")) {

				char filename[MAX_PATH];

				OPENFILENAMEA ofn;
				ZeroMemory(&filename, sizeof(filename));
				ZeroMemory(&ofn, sizeof(ofn));
				ofn.lStructSize = sizeof(ofn);
				ofn.hwndOwner = NULL; 
				ofn.lpstrFilter = "Executables\0*.exe\0Dynamic Link Libraries\0*.dll\0Drivers\0*.sys";
				ofn.lpstrFile = filename;
				ofn.nMaxFile = MAX_PATH;
				ofn.lpstrTitle = "Select your file.";
				ofn.Flags = OFN_DONTADDTORECENT | OFN_FILEMUSTEXIST;
				GetOpenFileNameA(&ofn);

				if (!std::filesystem::exists(filename)) {
					MessageBoxA(0, "Couldn't find file!", "Error", 0);
				}
				else {
					path = filename;
					try {
						funcs = inter::load_context(path);
					}
					catch (std::runtime_error e)
					{
						MessageBoxA(0, e.what(), "Exception", 0);
						path = "";
					}
					selected_func = 0;
					funcs_to_obfuscate.clear();
					
				}

			}

			ImGui::EndMenu();
		}

		ImGui::EndMenuBar();
	}

	if (path.size()) {

		ImGui::PushStyleColor(ImGuiCol_ChildBg, ImVec4(0.12f, 0.12f, 0.12f, 0.94f));
		ImGui::BeginChild("selectionpanel", ImVec2(100, 800), true, ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse);
		if (ImGui::Button("Protection", ImVec2(100, 100)))
			panel = 0;
		if (ImGui::Button("About", ImVec2(100, 100)))
			panel = 1;
		ImGui::EndChild();


		if (panel == 0) {
			ImGui::SetNextWindowPos(ImVec2(100, 25));

			ImGui::PushStyleColor(ImGuiCol_ChildBg, ImVec4(0.24f, 0.24f, 0.24f, 0.94f));
			if (ImGui::BeginChild("optionpanel", ImVec2(300, 775), true, ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoMove )) {

			
				ImGui::SetNextItemWidth(300);
				ImGui::InputText("", func_name, 1024);

				if (ImGui::TreeNode("Added functions")) {
					for (int i = 0; i < funcs_to_obfuscate.size(); i++)
					{
						if (ImGui::Button(funcs_to_obfuscate.at(i).name.c_str()))
							selected_func = funcs_to_obfuscate.at(i).id;

					}

					ImGui::TreePop();
				}

				if (ImGui::TreeNode("Functions")) {
					for (int i = 0; i < funcs.size(); i++)
					{
						if (funcs.at(i).size >= 5 && (funcs.at(i).name.find(func_name) != std::string::npos)) {
							if (ImGui::Button(funcs.at(i).name.c_str()))
								selected_func = funcs.at(i).id;
						}
					
					}

					ImGui::TreePop();
				}

				if (ImGui::TreeNode("Misc")) {
					ImGui::Checkbox("Obfuscate entry point", &obf_entry_point);
					ImGui::TreePop();
				}

				
				if (ImGui::Button("Add all")) {

					for (auto func = funcs.begin(); func != funcs.end(); ++func) {

						funcs_to_obfuscate.push_back(*func);
						func = funcs.erase(func);
						func--;

					}

				}

				if (ImGui::Button("Compile")) {
					try {
						inter::run_obfuscator(funcs_to_obfuscate, obf_entry_point);
					}
					catch (std::runtime_error e)
					{
						MessageBoxA(0, e.what(), "Exception", 0);
						path = "";
						//std::cout << "Runtime error: " << e.what() << std::endl;
					}

					MessageBoxA(0, "Compiled", "Success", 0);

				}

				ImGui::EndChild();
			}
			
			ImGui::SetNextWindowPos(ImVec2(400, 25));
			ImGui::PushStyleColor(ImGuiCol_ChildBg, ImVec4(0.48f, 0.48f, 0.48f, 0.94f));
			ImGui::BeginChild("functionpanel", ImVec2(880,775), true, ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse);


			
			auto already_added = std::find_if(funcs_to_obfuscate.begin(), funcs_to_obfuscate.end(), [&](const pdbparser::sym_func infunc) { return infunc.id == selected_func; });
			if (already_added != funcs_to_obfuscate.end()) {

				auto func = already_added;
				ImGui::Text("Name : %s", func->name.c_str());
				ImGui::Text("Address : %x", func->offset);
				ImGui::Text("Size : %i bytes", func->size);

				ImGui::Checkbox("Control flow flattening", &func->ctfflattening);
				ImGui::Checkbox("Immediate MOV obfuscation", &func->movobf);
				ImGui::Checkbox("Mutate", &func->mutateobf);
				ImGui::Checkbox("LEA obfuscation", &func->leaobf);
				ImGui::Checkbox("Anti disassembly", &func->antidisassembly);
			}
			else {

				auto func = &funcs.at(selected_func);
				ImGui::Text("Name : %s", func->name.c_str());
				ImGui::Text("Address : %x", func->offset);
				ImGui::Text("Size : %i bytes", func->size);

				ImGui::Checkbox("Control flow flattening", &func->ctfflattening);
				ImGui::Checkbox("Immediate MOV obfuscation", &func->movobf);
				ImGui::Checkbox("Mutate", &func->mutateobf);
				ImGui::Checkbox("LEA obfuscation", &func->leaobf);
				ImGui::Checkbox("Anti disassembly", &func->antidisassembly);

				if (ImGui::Button("Add to list")) {

					if (std::find_if(funcs_to_obfuscate.begin(), funcs_to_obfuscate.end(), [&](const pdbparser::sym_func infunc) {return infunc.id == func->id; }) == funcs_to_obfuscate.end()) {
						funcs_to_obfuscate.push_back(*func);
						funcs.erase(funcs.begin() + selected_func);
					}
				}
			}
			
			ImGui::SetCursorPosY(700);
			ImGui::Text(path.c_str());

			ImGui::EndChild();

			ImGui::PopStyleColor();

			ImGui::PopStyleColor();

		}
		else {

		}

		ImGui::PopStyleColor();

		
	}

	ImGui::End();

}