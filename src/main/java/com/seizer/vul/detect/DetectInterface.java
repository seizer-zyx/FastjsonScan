package com.seizer.vul.detect;

import java.util.ArrayList;

public interface DetectInterface {

    /**
     * 报错识别Fastjson
     * return Boolean
     */
    Boolean DetectError();

    /**
     * 版本检测
     * return String
     */
    String DetectVersion();

    /**
     * 引入依赖检测
     * return ArrayList
     */
    ArrayList<String> DetectDependency();

    /**
     * AutoType检测
     * return Boolean
     */
    Boolean DetectAutoType();

    /**
     * 出网检测
     * return Boolean
     */
    Boolean DetectDnsLog();
}
