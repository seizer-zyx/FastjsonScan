package com.seizer.vul.util;

import org.apache.commons.text.StringSubstitutor;

import java.util.ArrayList;
import java.util.Map;

public class PayloadFactory {

    public static String loadTemplate(String payloadTem, Map<String, String> params) {
        return StringSubstitutor.replace(payloadTem, params);
    }


    public static ArrayList<String> getPayloads() {
        return null;
    }




}
