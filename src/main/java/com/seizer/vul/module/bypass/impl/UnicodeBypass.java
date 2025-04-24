package com.seizer.vul.module.bypass.impl;

import com.seizer.vul.module.bypass.BypassInterface;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class UnicodeBypass implements BypassInterface {

    final static Pattern Jsoncompile = Pattern.compile("\"((?:\\\\.|[^\"\\\\])*)\"");

    public String transform(String payload) {
        Matcher matcher = Jsoncompile.matcher(payload);
        while (matcher.find()) {
            String value = matcher.group(1);
            payload = payload.replace(value, encodeToUnicode(value));
        }
        return payload;
    }

    /**
     * Unicode全编码
     */
    public String encodeToUnicode(String input) {
        StringBuilder sb = new StringBuilder();
        for (char c : input.toCharArray()) {
            sb.append("\\u");
            String hex = Integer.toHexString(c).toLowerCase();
            sb.append(new String(new char[4-hex.length()]).replace("\0", "0"));
            sb.append(hex);
        }
        return sb.toString();
    }
}
