package com.buptnsrc.krrecover.enums;

/**
 * 该枚举类用来存放一些全局性信息
 */
public enum GlobalEnum implements  StringEnum
{
    // 白名单
    WHITE_LIST("whiteList"),
    // 可疑名单
    SUSPICIOUS_LIST("suspiciousList"),
    // 沙盒日志前缀
    SANDBOX_LOG_PREFIX("sandboxLog_"),
    // 包名
    PARENT_PACKAGENAME("com.buptnsrc.krrecover"),
    // 子APP包名
    SUBAPP_PACKAGENAME("com.buptnsrc.krrecoversub");
    ;
    // 用来存放枚举变量所代表的字符串
    private String message;


    GlobalEnum(String message)
    {
        this.message = message;
    }

    @Override
    public String getString()
    {
        return this.message;
    }
}