package burp.scanner;

import burp.*;
import burp.backend.IBackend;
import burp.backend.platform.Ceye;
import burp.poc.IPOC;
import burp.poc.impl.*;
import burp.utils.HttpHeader;
import burp.utils.HttpUtils;
import burp.utils.ScanItem;
import burp.utils.Utils;
import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONArray;
import com.alibaba.fastjson.JSONObject;

import java.util.*;
import java.util.stream.Collectors;

import static burp.IRequestInfo.CONTENT_TYPE_MULTIPART;

public class Log4j2Scanner implements IScannerCheck {
    private BurpExtender parent;
    private IExtensionHelpers helper;
    private IBackend backend;

    private final String[] HEADER_BLACKLIST = new String[]{
            "content-length",
            "cookie",
            "host",
            "content-type",
            "authorization",
            "authenticate"
    };


    private final String[] HEADER_GUESS = new String[]{
            "User-Agent",
            "Referer",
            "X-Client-IP",
            "X-Remote-IP",
            "X-Remote-Addr",
            "X-Forwarded-For",
            "X-Originating-IP",
            "Originating-IP",
            "CF-Connecting_IP",
            "True-Client-IP",
            "Originating-IP",
            "X-Real-IP",
            "Forwarded",
            "X-Api-Version",
            "X-Wap-Profile",
            "Contact",
            "If-Modified-Since"
    };

    private final String[] STATIC_FILE_EXT = new String[]{
            "png",
            "jpg",
            "gif",
            "pdf",
            "bmp",
            "js",
            "css",
            "ico",
            "woff",
            "woff2",
            "ttf",
            "otf",
            "ttc",
            "svg",
            "psd",
            "exe",
            "zip",
            "rar",
            "7z",
            "msi",
            "tar",
            "gz",
            "mp3",
            "mp4",
            "mkv",
            "swf",
            "xls",
            "xlsx",
            "doc",
            "docx",
            "ppt",
            "pptx",
            "iso"
    };

    private IPOC[] pocs;

    public Log4j2Scanner(final BurpExtender newParent) {
        this.parent = newParent;
        this.helper = newParent.helpers;
        // this.pocs = new IPOC[]{new POC1(), new POC2(), new POC3(), new POC4(), new POC11()};
         this.pocs = new IPOC[]{new POC2(),new POC7(),new POC10(),new POC11()};
         this.backend = new Ceye();
        if (this.backend.getState()) {
            parent.stdout.println("[!] log4j2Scan loaded successfully!");
            parent.stdout.println("[!] modified by p1n93r.\r\n");
        } else {
            parent.stdout.println("[-] backend init failed!\r\n");
        }
    }

    public String urlencodeForTomcat(String exp) {
        exp = exp.replace("{", "%7b");
        exp = exp.replace("}", "%7d");
        return exp;
    }

    @Override
    public List<IScanIssue> doPassiveScan(IHttpRequestResponse baseRequestResponse) {
        IRequestInfo req = this.parent.helpers.analyzeRequest(baseRequestResponse);
        List<IScanIssue> issues = new ArrayList<>();
        if (!isStaticFile(req.getUrl().toString())) {
            parent.stdout.println(String.format("[*] scanning: %s", req.getUrl()));
            Map<String, ScanItem> domainMap = new HashMap<>();
            domainMap.putAll(paramsFuzz(baseRequestResponse, req));
            domainMap.putAll(headerFuzz(baseRequestResponse, req));
            try {
                parent.stdout.println("[*] waitting 60s,then to get query log.");
                //sleep 60s, wait for network delay.
                Thread.sleep(60000);
            } catch (InterruptedException e) {
                parent.stderr.println(String.format("[-] an error has occurred: %s",e.getMessage()));
            }
            issues.addAll(finalCheck(baseRequestResponse, req, domainMap));
            parent.stdout.println(String.format("[*] scan complete: %s", req.getUrl()));
        }
        return issues;
    }

    private boolean isStaticFile(String url) {
        return Arrays.stream(STATIC_FILE_EXT).anyMatch(s -> s.equalsIgnoreCase(HttpUtils.getUrlFileExt(url)));
    }

    private Collection<IPOC> getSupportedPOCs() {
        return Arrays.stream(pocs).filter(p -> Arrays.stream(backend.getSupportedPOCTypes()).anyMatch(c -> c == p.getType())).collect(Collectors.toList());
    }


    /**
     * 定制化DNS请求的前缀格式为：POST.124.207.152.162.oauth.oauth.token
     * 对应：POST 124.207.152.162/oauth/oauth/token
     * 不携带端口
     */
    private String getReqTag(IHttpRequestResponse baseRequestResponse, IRequestInfo req){
        List<String> requestHeader = req.getHeaders();
        // 循环获取参数，判断类型，进行加密处理后，再构造新的参数，合并到新的请求包中。
        //第一行请求包含请求方法、请求uri、http版本
        String firstrequestHeader = requestHeader.get(0);
        String[] firstheaders = firstrequestHeader.split(" ");
        String uri = firstheaders[1].split("\\?")[0].replace("/",".");
        if (firstheaders[1].split("\\?")[0].replace("/",".").length() > 25) {
            uri = uri.substring(0, 25);
            if (uri.endsWith(".")) {
                uri = uri.substring(0,uri.length()-1);
            }
        }
        if (uri.endsWith(".")) {
            uri = uri.substring(0,uri.length()-1);
        }
        IHttpService httpService = baseRequestResponse.getHttpService();
        String host = httpService.getHost();
        return firstheaders[0].trim() + "." + host  + uri + ".";
    }


    /**
     * fuzz header,不包括HEADER_BLACKLIST中的header，所以不fuzz Cookie等header
     * fuzz header也采用一次请求的方式，防止发送请求过多被ban
     */
    private Map<String, ScanItem> headerFuzz(IHttpRequestResponse baseRequestResponse, IRequestInfo req) {
        List<String> headers = req.getHeaders();
        String requestLine = headers.get(0);
        String logPrefix = getReqTag(baseRequestResponse,req);
        Map<String, ScanItem> domainMap = new HashMap<>();
        try {
            byte[] rawRequest = baseRequestResponse.getRequest();
            String tmpDomain = backend.getNewPayload();
            List<String> guessHeaders = new ArrayList(Arrays.asList(HEADER_GUESS));
            for (IPOC poc : getSupportedPOCs()) {
                ArrayList<HttpHeader> allHeaders = new ArrayList<>();
                // 先处理本来有的header
                for (int i = 1; i < headers.size(); i++) {
                    HttpHeader header = new HttpHeader(headers.get(i));
                    if (Arrays.stream(HEADER_BLACKLIST).noneMatch(h -> h.equalsIgnoreCase(header.name))) {
                        List<String> needSkipheader = guessHeaders.stream().filter(h -> h.equalsIgnoreCase(header.name)).collect(Collectors.toList());
                        needSkipheader.forEach(guessHeaders::remove);
                        header.value = poc.generate(Utils.confusionChars((logPrefix+tmpDomain).split("")));
                    }else{
                        // 黑名单中的header不能改，原样添加进去
                        allHeaders.add(new HttpHeader(header.toString()));
                    }
                }
                // 然后处理本扫描器中预测的header
                for (String headerName : guessHeaders) {
                    allHeaders.add(new HttpHeader(String.format("%s: %s", headerName, poc.generate(Utils.confusionChars((logPrefix+tmpDomain).split(""))))));
                }
                if(allHeaders.size()!=0){
                    ArrayList<String> headersStr = new ArrayList<>();
                    for (HttpHeader header : allHeaders) {
                        headersStr.add(header.toString());
                    }
                    // 记得将请求行添加进来
                    headersStr.add(0,requestLine);
                    byte[] tmpRawRequest = helper.buildHttpMessage(headersStr, Arrays.copyOfRange(rawRequest, req.getBodyOffset(), rawRequest.length));
                    IHttpRequestResponse tmpResponse = parent.callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), tmpRawRequest);
                    domainMap.put(tmpDomain, new ScanItem(true,"vul in header", tmpResponse));
                }

            }
        } catch (Exception ex) {
            parent.stderr.println(String.format("[-] an error has occurred: %s",ex.getMessage()));
        }
        return domainMap;
    }


    /**
     * fuzz以下内容:
     * 1. Cookie中的键值对
     * 2. HTTP Form请求参数：test=hello
     * 3. JSON格式的请求参数：{'test':'hello'}
     * 4. JSON和Form混合的方式：name=p1n93r&json={'test':'hello'}
     */
    private Map<String, ScanItem> paramsFuzz(IHttpRequestResponse baseRequestResponse, IRequestInfo req) {
        String logPrefix = getReqTag(baseRequestResponse,req);
        Map<String, ScanItem> domainMap = new HashMap<>();

        // 先处理json格式的请求，包括json和form混合的方式
        // 先处理单纯的json格式
        if(req.getContentType()==IRequestInfo.CONTENT_TYPE_JSON){
            for (IPOC poc : getSupportedPOCs()) {
                String dnslogDomain = backend.getNewPayload();
                String exp = poc.generate(Utils.confusionChars((logPrefix+dnslogDomain).split("")));
                String body = getBody(baseRequestResponse, req);
                //将body转为Json对象
                Object jsonObject = JSON.parse(body);
                // 将exp填充到json中，考虑了json递归的问题
                Object newJsonBody = analysisJson(jsonObject, exp);
                String newBody = newJsonBody.toString();
                byte[] bytes = newBody.getBytes();
                // 获取请求头
                List<String> requestHeader = req.getHeaders();
                byte[] newRequest = helper.buildHttpMessage(requestHeader, bytes);
                IHttpRequestResponse tmpResponse = parent.callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), newRequest);
                tmpResponse.getResponse();
                domainMap.put(dnslogDomain, new ScanItem(false,"vul in json param", tmpResponse));
            }
        }else{
            // 以下为非json格式的请求
            byte[] rawRequest = baseRequestResponse.getRequest();
            // 一次性将exp填充到HTTP请求中，防止发送过多的请求，导致被ban
            String tmpDomain = backend.getNewPayload();
            for (IPOC poc : getSupportedPOCs()) {
                ArrayList<IParameter> allParams = new ArrayList<>();
                for (IParameter param : req.getParameters()) {
                    try {
                        String exp = poc.generate(Utils.confusionChars((logPrefix + tmpDomain).split("")));
                        boolean hasModify = false;
                        // 根据不同的请求类型，选择是否需要URL编码
                        switch (param.getType()) {
                            case IParameter.PARAM_URL:
                            case IParameter.PARAM_BODY:

                                // URL编码只编码非CONTENT_TYPE_MULTIPART请求类型
                                if (req.getContentType() != CONTENT_TYPE_MULTIPART) {
                                    exp = helper.urlEncode(exp);
                                    exp = urlencodeForTomcat(exp);
                                }
                                // 但是还有一种情况例外，如果是CONTENT_TYPE_MULTIPART请求，但是参数是在URL中，此时仍旧需要编码
                                if (req.getContentType() == CONTENT_TYPE_MULTIPART && param.getType() == IParameter.PARAM_URL) {
                                    exp = helper.urlEncode(exp);
                                    exp = urlencodeForTomcat(exp);
                                }
                                hasModify = true;

                                // 获取参数值，判断是否为json字符串（form和json请求混合的情况）
                                String value = param.getValue();
                                if(value!=null&&!"".equals(value.trim())){
                                    value = helper.urlDecode(value);
                                    boolean isjson = isjson(value);
                                    if(isjson){
                                        String dnsDomain = backend.getNewPayload();
                                        String generateExp = poc.generate(Utils.confusionChars((logPrefix + dnsDomain).split("")));
                                        Object valueObject = JSON.parse(value);
                                        Object vulJson = analysisJson(valueObject,generateExp);
                                        String newExp = helper.urlEncode(vulJson.toString());
                                        newExp = urlencodeForTomcat(newExp);
                                        IParameter newParam = helper.buildParameter(param.getName(),newExp, param.getType());
                                        byte[] tmpNewRequest = helper.updateParameter(rawRequest, newParam);
                                        IHttpRequestResponse tmpResponse = parent.callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), tmpNewRequest);
                                        tmpResponse.getResponse();
                                        domainMap.put(dnsDomain, new ScanItem(false, "vul in param", tmpResponse));
                                    }
                                }

                                break;
                            case IParameter.PARAM_COOKIE:
                                // 测试发现，springboot的cookie不需要编码，而Tomcat遇到{}符号直接截断
                                // Tomcat Cookie编码的话，后台得到的也是编码的数据，不是解码的，log4j也打不了
                                // 所以综合考虑，Cookie直接不编码才是最稳妥的
                                // 但是Cookie有个问题，需要考虑有可能Cookie中的某个键值对可能是身份认证用，需要跳过它
                                // 所以Cookie还是选择控制变量法比较好，多发几个请求
                                String dnsDomain = backend.getNewPayload();
                                String generateExp = poc.generate(Utils.confusionChars((logPrefix + dnsDomain).split("")));
                                IParameter newParam = helper.buildParameter(param.getName(), generateExp, param.getType());
                                byte[] tmpNewRequest = helper.updateParameter(rawRequest, newParam);
                                IHttpRequestResponse tmpResponse = parent.callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), tmpNewRequest);
                                tmpResponse.getResponse();
                                domainMap.put(dnsDomain, new ScanItem(false, "vul in param", tmpResponse));
                                break;
                            // 剩下的不支持
                            case IParameter.PARAM_JSON:
                            case IParameter.PARAM_XML:
                            case IParameter.PARAM_MULTIPART_ATTR:
                            case IParameter.PARAM_XML_ATTR:
                            default:
                        }
                        // 先不管是否为json和form混合的形式，直接先全部按照form形式进行处理
                        if (hasModify) {
                            IParameter newParam = helper.buildParameter(param.getName(), exp, param.getType());
                            allParams.add(newParam);
                        }
                    } catch (Exception ex) {
                        parent.stderr.println(String.format("[-] an error has occurred: %s", ex.getMessage()));
                    }
                }
                if(allParams.size()!=0){
                    byte[] tmpRequest = rawRequest;
                    for (IParameter param : allParams) {
                        tmpRequest = helper.updateParameter(tmpRequest, param);
                    }
                    IHttpRequestResponse tmpResponse = parent.callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), tmpRequest);
                    tmpResponse.getResponse();
                    domainMap.put(tmpDomain, new ScanItem(false,"vul in param", tmpResponse));
                }
            }
        }
        // 不考虑CONTENT_TYPE_MULTIPART下的json串了，情况太少了
        return domainMap;
    }


    /**
     * 判断是否为json字符串(包括json数组)
     */
    private boolean isjson(String str){
        try {
            JSONObject.parse(str);
            return  true;
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * 递归遍历json对象
     */
    public Object analysisJson(Object objJson,String poc){
        //如果obj为json数组
        if(objJson instanceof JSONArray){
            JSONArray objArray = (JSONArray)objJson;
            for (int i = 0; i < objArray.size(); i++) {
                Object item = objArray.get(i);
                // 如果是数组内的字符串，则去除字符串，添加poc
                if(item instanceof String){
                    objArray.remove(item);
                    objArray.add(i,poc);
                    continue;
                }
                analysisJson(objArray.get(i),poc);
            }
        }else if(objJson instanceof JSONObject){
            //如果为json对象
            JSONObject jsonObject = (JSONObject)objJson;
            for (String s : jsonObject.keySet()) {
                Object object = jsonObject.get(s);
                //如果得到的是数组
                if (object instanceof JSONArray) {
                    JSONArray objArray = (JSONArray) object;
                    analysisJson(objArray,poc);
                }
                //如果key中是一个json对象
                else if (object instanceof JSONObject) {
                    analysisJson(object,poc);
                }
                //如果key中是其他
                else {
                    jsonObject.put(s,poc);
                }
            }
        }
        return objJson;
    }



    /**
     * 获取请求的body内容，返回body字符串
     */
    public String getBody(IHttpRequestResponse baseRequestResponse, IRequestInfo requestInfo){
        int bodyOffset = requestInfo.getBodyOffset();
        byte[] byteRequest = baseRequestResponse.getRequest();
        //byte[] to String
        String request = new String(byteRequest);
        return request.substring(bodyOffset);
    }



    private List<IScanIssue> finalCheck(IHttpRequestResponse baseRequestResponse, IRequestInfo req, Map<String, ScanItem> domainMap) {
        List<IScanIssue> issues = new ArrayList<>();
        if (backend.flushCache(domainMap.size())) {
            for (Map.Entry<String, ScanItem> domainItem :
                    domainMap.entrySet()) {
                ScanItem item = domainItem.getValue();
                boolean hasIssue = backend.checkResult(domainItem.getKey());
                if (hasIssue) {
                    issues.add(new Log4j2Issue(baseRequestResponse.getHttpService(),
                            req.getUrl(),
                            new IHttpRequestResponse[]{baseRequestResponse, item.tmpResponse},
                            "Log4j2 RCE Detected",
                            String.format("Vulnerable type: %s ,Vul info: %s", item.isHeader ? "header" : "param", item.info),
                            "High"));
                }
            }
        } else {
            parent.stdout.println("[-] get backend result failed!\r\n");
        }
        return issues;
    }

    private String getTypeName(int typeId) {
        switch (typeId) {
            case IParameter.PARAM_URL:
                return "URL";
            case IParameter.PARAM_BODY:
                return "Body";
            case IParameter.PARAM_COOKIE:
                return "Cookie";
            case IParameter.PARAM_JSON:
                return "Body-json";
            case IParameter.PARAM_XML:
                return "Body-xml";
            case IParameter.PARAM_MULTIPART_ATTR:
                return "Body-multipart";
            case IParameter.PARAM_XML_ATTR:
                return "Body-xml-attr";
            default:
                return "unknown";
        }
    }

    @Override
    public List<IScanIssue> doActiveScan(IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint) {
        return null;
    }

    @Override
    public int consolidateDuplicateIssues(IScanIssue existingIssue, IScanIssue newIssue) {
        return 0;
    }
}
