#include "main.h"

static ImGuiTextBuffer log_buff{};

extern void Log(const char* const fmt, ...) {
	va_list args;
	va_start(args, fmt);
	log_buff.appendfv(fmt, args);
	log_buff.append("\n");
	va_end(args);
}

extern void draw_log_window(void) {
	static bool log_scroll{ true };

	ImGui::Checkbox("AutoScroll", &log_scroll);
	ImGui::SameLine();
	if (ImGui::Button("Clear")) {
		log_buff.clear();
	}
	ImGui::BeginChild("log_scroll_region", ImVec2{}, true, ImGuiWindowFlags_NoScrollbar);
	ImGui::PushStyleVar(ImGuiStyleVar_ItemSpacing, ImVec2(0, 0));
	ImGui::TextUnformatted(log_buff.begin(), log_buff.end());
	ImGui::PopStyleVar();
	if (log_scroll && (ImGui::GetScrollY() >= ImGui::GetScrollMaxY()))
		ImGui::SetScrollHereY(1.0f);
	ImGui::EndChild();
}