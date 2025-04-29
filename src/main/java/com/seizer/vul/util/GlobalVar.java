package com.seizer.vul.util;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import java.security.SecureRandom;

public class GlobalVar {

    final public static String DNSLOG_PROVIDER = "dnsLogModule.provider";

    final public static String ERROR_MODULE = "payloadModule.DetectError";

    final public static String DNSLOG_MODULE = "payloadModule.DetectDnsLog";

    final public static String DELAY_MODULE = "payloadModule.DetectDnsLog";

    final public static String AUTOTYPE_MODULE = "payloadModule.DetectAutoType";


    final public static String VERSION_MODULE = "payloadModule.DetectVersionByDnsLog";

    final public static String DEPENDENCY_MODULE = "payloadModule.DetectDependency";
    final public static String DEPENDENCY_MODULE_DEPENDLIST = "payloadModule.DetectDependency.DependencyList";


    // 创建不安全的 TrustManager
    public static X509TrustManager createUnsafeTrustManager() {
        return new X509TrustManager() {
            @Override
            public void checkClientTrusted(java.security.cert.X509Certificate[] chain, String authType) {}
            @Override
            public void checkServerTrusted(java.security.cert.X509Certificate[] chain, String authType) {}
            @Override
            public java.security.cert.X509Certificate[] getAcceptedIssuers() {
                return new java.security.cert.X509Certificate[]{};
            }
        };
    }
    // 创建不安全的 SSLSocketFactory
    public static SSLSocketFactory createUnsafeSSLSocketFactory() {
        try {
            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(null, new TrustManager[]{createUnsafeTrustManager()}, new SecureRandom());
            return sslContext.getSocketFactory();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

}
