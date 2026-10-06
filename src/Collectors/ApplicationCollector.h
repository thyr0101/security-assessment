#pragma once
#include "../Models.h"
namespace sa {
std::vector<ApplicationDefinition> DefaultApplicationList();
std::vector<ApplicationFinding> CollectApplications(
    const std::vector<ApplicationDefinition>& defs);
}