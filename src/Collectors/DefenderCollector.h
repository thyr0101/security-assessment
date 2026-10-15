#pragma once
#include "../Models.h"
namespace sa {
DefenderInfo CollectDefenderInfo(bool registrationOnly = false);
Tri PeriodicScanningFromMode(const std::wstring& mode);
}
