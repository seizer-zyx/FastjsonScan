package com.seizer.vul.detect;

import com.seizer.vul.module.bypass.impl.UnicodeBypass;
import com.seizer.vul.module.dnslog.DnsLogAbstract;
import com.seizer.vul.util.GlobalVar;
import com.seizer.vul.util.PayloadFactory;
import com.seizer.vul.util.YamlReader;
import okhttp3.*;

import java.io.IOException;
import java.net.SocketTimeoutException;
import java.util.*;
import java.util.concurrent.TimeUnit;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static com.seizer.vul.util.GlobalVar.createUnsafeSSLSocketFactory;
import static com.seizer.vul.util.GlobalVar.createUnsafeTrustManager;


public class Detect implements DetectInterface{

    final private YamlReader yamlReader = YamlReader.getInstance();
    final private DnsLogAbstract dnsLogProvider;

    private String targetUrl;

    public DetectResult detectResult;

    // bypass开关，默认为false
    private boolean bypass;


    final static private OkHttpClient httpClient = new OkHttpClient.Builder()
            .followRedirects(false)
            .connectTimeout(30, TimeUnit.SECONDS)
            .readTimeout(10, TimeUnit.SECONDS)
            .sslSocketFactory(createUnsafeSSLSocketFactory(), createUnsafeTrustManager())
            .hostnameVerifier((hostname, session) -> true)
            .build();

    public Map<String, String> headers = new HashMap<>();

    public Detect(String targetUrl, Boolean bypass) {
        this.targetUrl = targetUrl;
        this.bypass = bypass;
        detectResult = new DetectResult(targetUrl, bypass);
        // 设置DnsLog模块
        String dnsLogProviderName = yamlReader.getString(GlobalVar.DNSLOG_PROVIDER);
        try {
            Class<?> dnsLogProviderClass = Class.forName("com.seizer.vul.module.dnslog.impl." + dnsLogProviderName);
            dnsLogProvider = (DnsLogAbstract) dnsLogProviderClass.newInstance();
        } catch (ClassNotFoundException e) {
            System.out.println("DnsLog模块未找到！");
            throw new RuntimeException(e);
        } catch (InstantiationException | IllegalAccessException e) {
            System.out.println("DnsLog模块初始化失败！");
            throw new RuntimeException(e);
        }
    }

    public Detect(String targetUrl) {
        this(targetUrl, false);
    }

    public void setHeaders(Map<String, String> headers) {
        this.headers = headers;
    }

    public void addHeader(String name, String value) {
        this.headers.put(name, value);
    }

    public String getTargetUrl() {
        return targetUrl;
    }

    public void setTargetUrl(String targetUrl) {
        this.targetUrl = targetUrl;
    }

    public boolean isBypass() {
        return bypass;
    }

    public void setBypass(boolean bypass) {
        this.bypass = bypass;
    }

    public DetectResult getDetectResult() {
        return detectResult;
    }

    private Response sendPayload(String payload) throws SocketTimeoutException {
        String userAgent = "Mozilla/5.0 (Windows NT 6.2; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/86.0.4240.198 Safari/537.36";

        RequestBody requestBody = RequestBody.create(payload, MediaType.parse("application/json"));

        Request.Builder requestBuilder = new Request.Builder()
                .url(targetUrl)
                .post(requestBody)
                .addHeader("User-Agent", userAgent)
                .addHeader("Accept", "*/*");

        for (Map.Entry<String, String> entry : headers.entrySet()) {
            requestBuilder.addHeader(entry.getKey(), entry.getValue());
        }

        Request request = requestBuilder.build();


        Response response = null;
        try {
            response = httpClient.newCall(request).execute();
        } catch (SocketTimeoutException e){
            throw new SocketTimeoutException();
        } catch (IOException e) {
            System.out.println("请求目标地址失败！");
            throw new RuntimeException(e);
        }
        return response;
    }

    private String getModuleDesc(String ModuleName) {
        LinkedHashMap<String, Object> Module = yamlReader.getLinkedHashMap(ModuleName);
        return (String) Module.get("description");
    }

    private ArrayList<String> getPayloads(String ModuleName) {
        LinkedHashMap<String, Object> Module = yamlReader.getLinkedHashMap(ModuleName);
        return (ArrayList<String>) Module.get("payloads");
    }

    @Override
    public Boolean DetectError() {
        ArrayList<String> payloads = getPayloads(GlobalVar.ERROR_MODULE);
        Boolean errResponse = false;
        Boolean vulExist = false;
        Pattern versionRegex = Pattern.compile("fastjson-version(\\s\\d.\\d.[0-9]+)");
        for (String payloadTem : payloads) {
            HashMap<String, String> params = new HashMap<>();
            String payload = PayloadFactory.loadTemplate(payloadTem, params);
            if (isBypass()) {
                payload = new UnicodeBypass().transform(payload);
            }
            try (Response response = sendPayload(payload)) {
                Matcher matcher = null;
                if (response.body() != null && (matcher = versionRegex.matcher(response.body().string())).find()) {
                    detectResult.setVersion(matcher.group(1).trim());
                    vulExist = true;
                    errResponse = true;
                }
                if (!response.isSuccessful()) {
                    vulExist = true;
                }
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        }
        detectResult.setErrExist(vulExist);
        detectResult.setErrResponse(errResponse);
        return errResponse;
    }

    @Override
    public String DetectVersion() {
        String version = null;
        Set<String> keySet = yamlReader.getLinkedHashMap(GlobalVar.VERSION_MODULE).keySet();
        for (String moduleName: keySet) {
            version = DetectVersion(GlobalVar.VERSION_MODULE + "." + moduleName);
            if (version != null) {
                detectResult.setVersion(version);
                return version;
            }
        }
        return null;
    }

    private String DetectVersion(String versionModule) {
        for (String payloadTem : getPayloads(versionModule)) {
            String dnsLogUrl = dnsLogProvider.getDnsLogUrl();
            HashMap<String, String> params = new HashMap<>();
            params.put("dnslog", dnsLogUrl);
            String payload = PayloadFactory.loadTemplate(payloadTem, params);
            if (isBypass()) {
                payload = new UnicodeBypass().transform(payload);
            }
            try {
                sendPayload(payload);
            } catch (SocketTimeoutException e) {
                throw new RuntimeException(e);
            }
        }
        String dnsLogRecord = dnsLogProvider.getDnsLogRecord();
        if (!dnsLogRecord.equals("[]")) {
            if (dnsLogRecord.contains("83")) {
                return "1.2.83";
            }
            return getModuleDesc(versionModule);
        }
        return null;
    }

    @Override
    public ArrayList<String> DetectDependency() {
        ArrayList<String> payloads = getPayloads(GlobalVar.DEPENDENCY_MODULE);
        ArrayList<String> dependencyExistList = new ArrayList<>();
        for (String payloadTem : payloads) {
            for (String dependency : yamlReader.getStringList(GlobalVar.DEPENDENCY_MODULE_DEPENDLIST)) {
                HashMap<String, String> params = new HashMap<>();
                params.put("dependency", dependency);
                String payload = PayloadFactory.loadTemplate(payloadTem, params);
                if (isBypass()) {
                    payload = new UnicodeBypass().transform(payload);
                }
                try (Response response = sendPayload(payload)) {
                    if (response.body() != null && response.body().string().contains(dependency) && !dependencyExistList.contains(dependency)) {
                        dependencyExistList.add(dependency);
                    }
                } catch (IOException e) {
                    throw new RuntimeException(e);
                }
            }
        }
        detectResult.setDependencyList(dependencyExistList);
        return dependencyExistList;
    }

    @Override
    public Boolean DetectAutoType() {
        ArrayList<String> payloads = getPayloads(GlobalVar.AUTOTYPE_MODULE);
        for (String payloadTem : payloads) {
            String dnsLogUrl = dnsLogProvider.getDnsLogUrl();
            HashMap<String, String> params = new HashMap<>();
            params.put("dnslog", dnsLogUrl);
            String payload = PayloadFactory.loadTemplate(payloadTem, params);
            if (isBypass()) {
                payload = new UnicodeBypass().transform(payload);
            }
            try {
                sendPayload(payload);
            } catch (SocketTimeoutException e) {
                throw new RuntimeException(e);
            }
        }
        String dnsLogRecord = dnsLogProvider.getDnsLogRecord();
        boolean autoType = !dnsLogRecord.equals("[]");
        detectResult.setAutoType(autoType);
        return autoType;
    }

    @Override
    public Boolean DetectDnsLog() {
        ArrayList<String> payloads = getPayloads(GlobalVar.DNSLOG_MODULE);
        for (String payloadTem : payloads) {
            String dnsLogUrl = dnsLogProvider.getDnsLogUrl();
            HashMap<String, String> params = new HashMap<>();
            params.put("dnslog", dnsLogUrl);
            String payload = PayloadFactory.loadTemplate(payloadTem, params);
            if (isBypass()) {
                payload = new UnicodeBypass().transform(payload);
            }
            try {
                sendPayload(payload);
            } catch (SocketTimeoutException e) {
                throw new RuntimeException(e);
            }
        }
        String dnsLogRecord = dnsLogProvider.getDnsLogRecord();
        boolean outNetwork = !dnsLogRecord.equals("[]");
        detectResult.setOutNetwork(outNetwork);
        return outNetwork;
    }

    @Override
    public Boolean DetectDelay() {
        ArrayList<String> payloads = getPayloads(GlobalVar.DELAY_MODULE);
        for (String payloadTem : payloads) {
            HashMap<String, String> params = new HashMap<>();
            params.put("value", new String(new char[20]).replace("\0", "a"));
            String payload = PayloadFactory.loadTemplate(payloadTem, params);
            if (isBypass()) {
                payload = new UnicodeBypass().transform(payload);
            }
            try {
                sendPayload(payload);
            } catch (SocketTimeoutException e) {
                detectResult.setDelayExist(true);
                return true;
            }
        }
        detectResult.setDelayExist(false);
        return false;
    }

    public static class DetectResult {
        public String url;
        public Boolean bypass;
        public Boolean errExist;
        public Boolean delayExist;
        public String version;
        public Boolean autoType;
        public Boolean outNetwork;
        public Boolean errResponse;
        public ArrayList<String> dependencyList;

        public DetectResult(String url, Boolean bypass) {
            this.url = url;
            this.bypass = bypass;
        }

        public void setErrExist(Boolean errExist) {
            this.errExist = errExist;
        }

        public void setDelayExist(Boolean delayExist) {this.delayExist = delayExist;}

        public void setVersion(String version) {
            this.version = version;
        }

        public void setAutoType(Boolean autoType) {
            this.autoType = autoType;
        }

        public void setOutNetwork(Boolean outNetwork) {
            this.outNetwork = outNetwork;
        }

        public void setErrResponse(Boolean errResponse) {
            this.errResponse = errResponse;
        }

        public void setDependencyList(ArrayList<String> dependencyList) {
            this.dependencyList = dependencyList;
        }

        @Override
        public String toString() {
            StringBuilder result = new StringBuilder(String.format("Scan Result:\n" +
                    "Target: %s\n" +
                    "Bypass: %s\n" +
                    "[+] 报错检测: %s\n" +
                    "[+] 延时检测: %s\n" +
                    "[+] 报错回显: %s\n" +
                    "[+] Fastjson 版本: %s\n" +
                    "[+] 网络状态判断: %s\n" +
                    "[+] AutoType 状态: %s\n" +
                    "[+] 依赖库信息:\n", url, bypass, errExist, delayExist, errResponse, version, outNetwork, autoType));
            if (dependencyList != null) {
                for (String dependency : dependencyList) {
                    result.append(String.format("%s\n", dependency));
                }
            }
            return result.toString();
        }
    }
}
