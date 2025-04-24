package com.seizer.vul.module.dnslog.impl;

import com.seizer.vul.module.dnslog.DnsLogAbstract;
import com.seizer.vul.util.CustomHelper;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;

import java.io.IOException;
import java.util.concurrent.TimeUnit;

public class DnsLogCn extends DnsLogAbstract {

    final private String dnslogDomainName;

    private String dnsLogCookieName;
    private String dnsLogCookieValue;

    final static private OkHttpClient httpClient = new OkHttpClient.Builder()
            .followRedirects(false)
            .connectTimeout(30, TimeUnit.SECONDS)
            .readTimeout(30, TimeUnit.SECONDS)
            .build();


    public DnsLogCn() {
        this.setExtensionName("DnsLogCn");
        this.dnslogDomainName = "http://dnslog.cn";
    }

    @Override
    public String getDnsLogUrl() {
        String url = this.dnslogDomainName + "/getdomain.php";
        String userAgent = "Mozilla/5.0 (Windows NT 6.2; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/86.0.4240.198 Safari/537.36";

        Request request = new Request.Builder().
                url(url)
                .addHeader("User-Agent", userAgent)
                .addHeader("Accept", "*/*")
                .build();

        try {
            try (Response response = httpClient.newCall(request).execute()) {
                int statusCode = response.code();

                if (statusCode != 200) {
                    throw new RuntimeException(
                            String.format(
                                    "%s 扩展-访问url-%s, 请检查本机是否可访问 %s",
                                    this.getExtensionName(),
                                    statusCode,
                                    url));
                }

                String cookie = response.header("Set-Cookie");
                String sessidKey = "PHPSESSID";
                String sessidValue = CustomHelper.getParam(cookie, sessidKey);

                this.dnsLogCookieName = sessidKey;
                this.dnsLogCookieValue = sessidValue;

                if (sessidValue == null || sessidValue.isEmpty()) {
                    throw new IllegalArgumentException(
                            String.format(
                                    "%s 扩展-访问站点 %s 时返回Cookie为空, 导致无法正常获取dnsLog数据, 请检查",
                                    this.getExtensionName(),
                                    this.dnslogDomainName));
                }

                if (response.body() != null) {
                    return response.body().string();
                } else {
                    throw new RuntimeException(
                            String.format(
                                    "%s 扩展-获取临时域名失败, 请检查本机是否可访问 %s",
                                    this.getExtensionName(),
                                    this.dnslogDomainName));
                }
            }
        } catch (IOException e) {
            throw new RuntimeException(String.format(
                    "%s 扩展-访问url超时, 请检查本机是否可访问 %s",
                    this.getExtensionName(),
                    url));
        }
    }

    @Override
    public String getDnsLogRecord() {
        String url = this.dnslogDomainName + "/getrecords.php";
        String userAgent = "Mozilla/5.0 (Windows NT 6.2; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/86.0.4240.198 Safari/537.36";


        Request request = new Request.Builder().
                url(url)
                .addHeader("User-Agent", userAgent)
                .addHeader("Accept", "*/*")
                .addHeader("Cookie", this.dnsLogCookieName + "=" + this.dnsLogCookieValue + ";")
                .build();

        try {
            Response response = httpClient.newCall(request).execute();
            String body = null;
            if (response.body() != null) {
                body = response.body().string();
            }

            if (!response.isSuccessful()) {
                throw new RuntimeException(
                        String.format(
                                "%s 扩展-%s内容有异常,异常内容: %s",
                                this.getExtensionName(),
                                this.dnslogDomainName,
                                body
                        )
                );
            }
            return body;
        } catch (IOException e) {
            throw new RuntimeException(String.format(
                    "%s 扩展-访问url超时, 请检查本机是否可访问 %s",
                    this.getExtensionName(),
                    url));
        }
    }
}
