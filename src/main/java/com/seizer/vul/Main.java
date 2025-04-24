package com.seizer.vul;

import com.seizer.vul.detect.Detect;
import org.apache.commons.cli.*;

public class Main {
    public static void main(String[] args) {
        // 定义选项
        Options options = new Options();
        options.addOption("u", "url", true, "Specify the URL (required)");
        options.addOption(null, "bypass", false, "Enable bypass mode");
        // 解析参数
        CommandLineParser parser = new DefaultParser();
        try {
            CommandLine cmd = parser.parse(options, args);
            // 获取参数值
            String url = cmd.getOptionValue("url");
            boolean bypass = cmd.hasOption("bypass");
            // 检查必填参数
            if (url == null) {
                System.err.println("Error: URL is required.");
                printHelp(options);
                return;
            }
            // 执行逻辑
            Start(url, bypass);
        } catch (ParseException e) {
            System.err.println("Error: " + e.getMessage());
            printHelp(options);
        }
    }
    // 打印帮助信息
    private static void printHelp(Options options) {
        HelpFormatter formatter = new HelpFormatter();
        formatter.printHelp("FastjsonScan", options);
    }

    private static void Start(String url, Boolean bypass) {
        Detect detect = new Detect(url, bypass);
        Detect.DetectResult detectResult = detect.getDetectResult();
        Boolean errResponse = detect.DetectError();
        Boolean outNetwork = detect.DetectDnsLog();
        if (outNetwork) {
            detect.DetectAutoType();
            if (detectResult.version == null) {
                detect.DetectVersion();
            }
        }
        if (errResponse) {
            detect.DetectDependency();
        }
        System.out.println(detectResult);
    }
}