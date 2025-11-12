// plugin_api.h
#pragma once

#include <string>
#include <vector>

// 插件初始化函数类型
// 返回 true 表示初始化成功，false 表示失败（MPS 会弹窗并卸载插件）
typedef bool (*PluginInitFunc)();

// 插件命令处理函数类型
// 参数：
//   - cmd: 命令名（如 "protect", "my_custom_cmd"）
//   - pid: 目标进程 PID（可能为 0）
//   - args: 命令后的额外参数列表
//   - response: 输出响应字符串（插件需填充）
// 返回 true 表示已处理该命令，false 表示未处理（交给 MPS 主逻辑或其他插件）
typedef bool (*PluginHandleCommandFunc)(
    const std::string& cmd,
    DWORD pid,
    const std::vector<std::string>& args,
    std::string& response
);

// 日志处理器函数指针类型（供 RegisterLogHandler 使用）
typedef void (*LogHandlerFn)(const char* level, const char* msg);

// 插件必须导出的函数（使用 extern "C" 防止 C++ 名称修饰）
extern "C" {

// 插件初始化入口（必须实现）
__declspec(dllexport) bool PluginInit();

// 可选：插件命令处理器（若需接管命令）
__declspec(dllexport) bool PluginHandleCommand(
    const std::string& cmd,
    DWORD pid,
    const std::vector<std::string>& args,
    std::string& response
);

// 可选：注册自定义日志处理器（需通过密钥认证）
// 此函数由 MPS 主程序提供，插件调用它来接管日志
__declspec(dllimport) bool RegisterLogHandler(
    const char* plugin_auth_key,
    LogHandlerFn custom_logger
);

}