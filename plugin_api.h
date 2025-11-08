// plugin_api.h
#pragma once

#include <string>
#include <vector>
#include <windows.h>  // 确保 DWORD 等类型已定义

// 插件初始化函数（返回 true 表示加载成功）
typedef bool (*PluginInitFunc)();

// 插件销毁函数（当前未使用，预留）
typedef void (*PluginDestroyFunc)();

// 插件命令处理函数
// - cmd: 命令名称
// - targetPid: 目标进程 PID（可为 0）
// - args: 额外参数列表
// - response: 返回给客户端的响应字符串
typedef bool (*PluginHandleCommandFunc)(
    const std::string& cmd,
    DWORD targetPid,
    const std::vector<std::string>& args,
    std::string& response
);