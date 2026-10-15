#pragma once
#include "../Models.h"
namespace sa {
std::vector<PrivacyFinding> CollectPrivacyFindings(HKEY machineRoot = HKEY_LOCAL_MACHINE, HKEY userRoot = HKEY_CURRENT_USER);
}