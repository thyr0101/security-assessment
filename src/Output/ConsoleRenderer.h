#pragma once
#include "../Models.h"
namespace sa {
enum class ReportView { Live, Export };
void RenderConsole(const AssessmentResult& r, ReportView view = ReportView::Live);
}