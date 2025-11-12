// plugin_api.h
#pragma once

#include <string>
#include <vector>

// 插件必须实现的初始化函数
typedef bool (*PluginInitFunc)();

// 插件可选实现的命令处理器
typedef bool (*PluginHandleCommandFunc)(
    const std::string& cmd,
    DWORD pid,
    const std::vector<std::string>& args,
    std::string& response
);

// 日志处理器类型
typedef void (*LogHandlerFn)(const char* level, const char* msg);

// 插件应声明（非定义）以下函数
extern "C" {
    __declspec(dllimport) bool RegisterLogHandler(
        const char* plugin_auth_key,
        LogHandlerFn custom_logger
    );
}