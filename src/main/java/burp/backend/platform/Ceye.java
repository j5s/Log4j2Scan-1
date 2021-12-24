package burp.backend.platform;

import burp.backend.IBackend;
import burp.poc.IPOC;
import burp.utils.HttpUtils;
import burp.utils.Utils;
import com.alibaba.fastjson.JSONArray;
import com.alibaba.fastjson.JSONObject;
import okhttp3.OkHttpClient;
import okhttp3.Response;

import java.io.*;
import java.util.Objects;
import java.util.Properties;
import java.util.Set;
import java.util.concurrent.*;


public class Ceye implements IBackend {
    OkHttpClient client = new OkHttpClient().newBuilder().
            connectTimeout(3000, TimeUnit.SECONDS).
            callTimeout(3000, TimeUnit.SECONDS).build();
    private static String platformUrl = "";
    private static String rootDomain = "";
    private static String token = "";
    private static final String CONFIG_NAME = "log4j_ceye.properties";
    private static final PrintWriter PRINT_WRITER = new PrintWriter(Utils.Callback.getStdout(), true);
    private static final PrintWriter ERROR_WRITER = new PrintWriter(Utils.Callback.getStderr(), true);
    private final Set<String> vulLogCache = new CopyOnWriteArraySet<>();

    private void getLogHeartbeat() {
        ScheduledExecutorService scheduledExecutorService = Executors.newScheduledThreadPool(10);
        Runnable runnable = () -> {
            // 定时查询下是否存在漏报的情况
            try {
                String getUrl=platformUrl + "v1/records?token=" + token + "&type=dns&filter=GET";
                String postUrl=platformUrl + "v1/records?token=" + token + "&type=dns&filter=POST";
                Response resp4get = client.newCall(HttpUtils.GetDefaultRequest(getUrl).build()).execute();
                Response resp4post = client.newCall(HttpUtils.GetDefaultRequest(postUrl).build()).execute();
                JSONObject getObject = JSONObject.parseObject(Objects.requireNonNull(resp4get.body()).string().toLowerCase());
                JSONObject postObject = JSONObject.parseObject(Objects.requireNonNull(resp4post.body()).string().toLowerCase());
                addLogCache(getObject);
                addLogCache(postObject);
            } catch (Exception ex) {
                ERROR_WRITER.write(String.format("[-] an error has occurred: %s", ex.getMessage()));
            }
        };
        // 三分钟查一次
        scheduledExecutorService.scheduleAtFixedRate(runnable,10,3 * 60,TimeUnit.SECONDS);
    }


    public Ceye() {
        String os = System.getProperty("os.name");
        File configFile;
        if (os.toLowerCase().startsWith("win")) {
            configFile = new File(CONFIG_NAME);
        }else{
            // 获取当前jar的路径
            String jarPath = Utils.Callback.getExtensionFilename();
            configFile = new File(jarPath.substring(0, jarPath.lastIndexOf(File.separator)) + File.separator + CONFIG_NAME);
        }
        if(!configFile.exists()){
            // 初始化配置文件
            try {
                boolean isOk = configFile.createNewFile();
                if(isOk){
                    Properties properties = new Properties();
                    properties.put("platformUrl","http://api.ceye.io/");
                    properties.put("rootDomain","xxxx.ceye.io");
                    properties.put("token","");
                    properties.store(new FileOutputStream(configFile), "log4j扫描插件ceye配置模板");
                    PRINT_WRITER.println(String.format("[!] please configure your own ceye,config path: %s",configFile.getAbsoluteFile()));
                }else{
                    ERROR_WRITER.write("[-] can't init the configure file");
                }
            } catch (IOException e) {
                ERROR_WRITER.write(String.format("[-] an error has occurred: %s",e.getMessage()));
            }
        }else{
            try{
                // 读取配置文件
                Properties properties = new Properties();
                properties.load(new FileInputStream(configFile));
                platformUrl = properties.getProperty("platformUrl");
                rootDomain = properties.getProperty("rootDomain");
                token = properties.getProperty("token");
                PRINT_WRITER.println(String.format("[!] platformUrl:%s, rootDomain:%s, token:%s",platformUrl,rootDomain,token));
                if("".equals(token)||token==null){
                    PRINT_WRITER.println(String.format("[!] please configure your own ceye in the config file:%s,and reload this extender!",configFile.getAbsoluteFile()));
                }else{
                    PRINT_WRITER.println("[!] init ceye configure success.");
                    PRINT_WRITER.println("[!] you can search '[maybe underreport vul]' in this log to get all log4j vul.");
                }
            }catch(IOException e){
                ERROR_WRITER.write(String.format("[-] an error has occurred: %s",e.getMessage()));
            }
        }
        getLogHeartbeat();
    }

    public Ceye(String rootDomain, String token) {
        Ceye.rootDomain = rootDomain;
        Ceye.token = token;
        getLogHeartbeat();
    }

    @Override
    public String getName() {
        return "Ceye.io";
    }

    @Override
    public String getNewPayload() {
        return Utils.getCurrentTimeMillis() + Utils.GetRandomString(5) + "." + rootDomain;
    }

    @Override
    public boolean checkResult(String domain) {
        try {
            Response resp = client.newCall(HttpUtils.GetDefaultRequest(platformUrl + "v1/records?token=" + token + "&type=dns&filter=" + domain.substring(0, domain.indexOf("."))).build()).execute();
            JSONObject jObj = JSONObject.parseObject(Objects.requireNonNull(resp.body()).string().toLowerCase());
            if (jObj.containsKey("data")) {
                if(((JSONArray) jObj.get("data")).size()>0){
                    // PRINT_WRITER.println(String.format("[+] found one vul: %s",domain));
                    return true;
                }
            }
        } catch (Exception ex) {
            ERROR_WRITER.println(String.format("[-] an error has occurred: %s",ex.getMessage()));
            return false;
        }
        return false;
    }

    @Override
    public boolean flushCache(int count) {
        return flushCache();
    }


    private void addLogCache(JSONObject jsonObject){
        if (jsonObject.containsKey("data")) {
            JSONArray jsonArray = (JSONArray) jsonObject.get("data");
            if(jsonArray.size()>0){
                // 遍历json array
                jsonArray.forEach(object -> {
                    JSONObject item = (JSONObject) object;
                    String logDomain = (String) item.get("name");
                    if(!vulLogCache.contains(logDomain)){
                        vulLogCache.add(logDomain);
                        PRINT_WRITER.println(String.format("[+] find one vul[maybe underreport vul],domain is %s",logDomain));
                    }
                });
            }
        }
    }


    @Override
    public boolean flushCache() {
        return true;
    }

    @Override
    public boolean getState() {
        return true;
    }

    @Override
    public int[] getSupportedPOCTypes() {
        return new int[]{IPOC.POC_TYPE_LDAP, IPOC.POC_TYPE_RMI};
    }
}
