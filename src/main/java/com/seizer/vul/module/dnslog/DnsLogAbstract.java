package com.seizer.vul.module.dnslog;

import java.util.concurrent.ThreadLocalRandom;

public abstract class DnsLogAbstract implements DnsLogInterface {
    private String extensionName = "";

    /**
     * 设置扩展名称 (必须的)
     */
    protected void setExtensionName(String value) {
        if (value == null || value.isEmpty()) {
            throw new IllegalArgumentException("DnsLog扩展-扩展名称不能为空");
        }
        this.extensionName = value;
    }

    /**
     * 获取扩展名称
     */
    @Override
    public String getExtensionName() {
        return this.extensionName;
    }

    @Override
    public String randCreator() {
        final String CHAR_SET = "0123456789abcdefghigklmnopqrstuvwxyz";
        final int LENGTH = 26;

        ThreadLocalRandom random = ThreadLocalRandom.current();
        char[] buffer = new char[LENGTH];

        for (int i = 0; i < LENGTH; i++) {
            buffer[i] = CHAR_SET.charAt(random.nextInt(CHAR_SET.length()));
        }

        return new String(buffer);
    }
}
