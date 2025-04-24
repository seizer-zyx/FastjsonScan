package com.seizer.vul.util;

import org.yaml.snakeyaml.Yaml;

import java.io.*;
import java.net.URISyntaxException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.*;

public class YamlReader {
    private static YamlReader instance;

    private static Map<String, Map<String, Object>> properties = new HashMap<>();

    private YamlReader() {
        try {
            InputStream configInputStream = null;
            Path jarDir = Paths.get(this.getClass().getProtectionDomain().getCodeSource().getLocation().toURI()).getParent();
            Path configPath = jarDir.resolve("resources/config.yml");
            try {
                configInputStream = new FileInputStream(configPath.toFile());
            } catch (FileNotFoundException e) {
                configInputStream = this.getClass().getClassLoader().getResourceAsStream("config.yml");
            }
            if (configInputStream == null) {
                System.out.println("读取config.yml异常");
            }
            properties = new Yaml().load(configInputStream);
        } catch (URISyntaxException e) {
            throw new RuntimeException(e);
        }
    }

    public static synchronized YamlReader getInstance() {
        if (instance == null) {
            instance = new YamlReader();
        }
        return instance;
    }

    /**
     * 获取yaml属性
     * 可通过 "." 循环调用
     * 例如这样调用: YamlReader.getInstance().getValueByKey("a.b.c.d")
     *
     * @param key
     * @return
     */
    public Object getValueByKey(String key) {
        String separator = ".";
        String[] separatorKeys = null;
        if (key.contains(separator)) {
            separatorKeys = key.split("\\.");
        } else {
            return properties.get(key);
        }
        Map<String, Map<String, Object>> finalValue = new HashMap<>();
        for (int i = 0; i < separatorKeys.length - 1; i++) {
            if (i == 0) {
                finalValue = (Map) properties.get(separatorKeys[i]);
                continue;
            }
            if (finalValue == null) {
                break;
            }
            finalValue = (Map) finalValue.get(separatorKeys[i]);
        }
        return finalValue == null ? null : finalValue.get(separatorKeys[separatorKeys.length - 1]);
    }

    public String getString(String key) {
        return String.valueOf(this.getValueByKey(key));
    }

    public String getString(String key, String defaultValue) {
        if (null == this.getValueByKey(key)) {
            return defaultValue;
        }
        return String.valueOf(this.getValueByKey(key));
    }

    public Boolean getBoolean(String key) {
        return (boolean) this.getValueByKey(key);
    }

    public Integer getInteger(String key) {
        return (Integer) this.getValueByKey(key);
    }

    public double getDouble(String key) {
        return (double) this.getValueByKey(key);
    }

    public List<String> getStringList(String key) {
        return (List<String>) this.getValueByKey(key);
    }

    public LinkedHashMap<String, Object> getLinkedHashMap(String key) {
        return (LinkedHashMap<String, Object>) this.getValueByKey(key);
    }
}