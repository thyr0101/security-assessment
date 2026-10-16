#pragma once
#include "../Models.h"
namespace sa {
std::vector<RegistryScanDefinition> DefaultRegistryScans();
std::vector<DirectoryScanDefinition> DefaultDirectoryScans();
std::vector<RegistryFinding> RunRegistryScans(const std::vector<RegistryScanDefinition>&);
std::vector<DirectoryFinding> RunDirectoryScans(const std::vector<DirectoryScanDefinition>&);
}
