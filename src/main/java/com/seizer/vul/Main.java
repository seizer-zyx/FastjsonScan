package com.seizer.vul;

import com.seizer.vul.detect.Detect;
import org.apache.commons.cli.*;

import java.util.HashMap;
import java.util.Map;

public class Main {
    public static void main(String[] args) {
        // 定义选项
        Options options = new Options();
        options.addOption("u", "url", true, "Specify the URL (required)");
        Option headerOption = new Option("h", "header", false, "Custom request header");
        headerOption.setArgs(Option.UNLIMITED_VALUES);
        options.addOption(headerOption);
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

            Map<String, String> headers = new HashMap<>();
            if (cmd.hasOption("h")) {
                String[] values = cmd.getOptionValues("h");
                for (String value : values) {
                    // 解析键值对
                    String[] parts = value.split(":");
                    if (parts.length == 2) {
                        headers.put(parts[0], parts[1]);
                    } else {
                        System.err.println("Invalid key-value pair: " + value);
                    }
                }
            }
            // 执行逻辑
            Detect detect = new Detect(url, bypass);
            detect.setHeaders(headers);
            Start(detect);
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

    private static void Start(Detect detect) {
        Detect.DetectResult detectResult = detect.getDetectResult();
        Boolean errResponse = detect.DetectError();
        Boolean outNetwork = detect.DetectDnsLog();
        if (outNetwork) {
            detect.DetectAutoType();
            if (detectResult.version == null) {
                detect.DetectVersion();
            }
        } else {
            detect.DetectDelay();
        }
        if (errResponse) {
            detect.DetectDependency();
        }
        System.out.println(detectResult);
    }
}