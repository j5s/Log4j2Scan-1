package burp.backend.platform;

import burp.backend.IBackend;
import burp.poc.IPOC;
import burp.utils.HttpUtils;
import burp.utils.Utils;
import com.alibaba.fastjson.JSONArray;
import com.alibaba.fastjson.JSONObject;
import okhttp3.*;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import java.io.IOException;
import java.io.PrintWriter;
import java.util.concurrent.TimeUnit;

/**
 * @author : p1n93r
 * @date : 2021/12/13 19:08
 */
public class CustomDnslog implements IBackend {

    OkHttpClient client = new OkHttpClient().newBuilder().authenticator(new Authenticator() {
        @Override
        public Request authenticate(@Nullable Route route, @NotNull Response response) throws IOException {
            String credential = Credentials.basic("root", "xxxxx");
            return response.request().newBuilder()
                    .header("Authorization", credential)
                    .build();
        }
    }).connectTimeout(3000, TimeUnit.SECONDS).callTimeout(3000, TimeUnit.SECONDS).build();


    String platformUrl = "http://xx.xx.xxx.xx:8888/";
    String rootDomain = "xxx.xxx.xxx.xx";

    public CustomDnslog(){}


    @Override
    public String getName() {
        return "Qingteng-Wglab-Dnslog";
    }

    @Override
    public String getNewPayload() {
        return Utils.getCurrentTimeMillis() + Utils.GetRandomString(5) + "." + rootDomain;
    }

    @Override
    public boolean checkResult(String domain) {
        try {
            String filterKeywords = domain.substring(0, domain.indexOf("."));
            Response resp = client.newCall(HttpUtils.GetDefaultRequest(platformUrl + "dns?search=%s&order=asc&offset=10".replaceAll("%s",filterKeywords) ).build()).execute();
            JSONObject jObj = JSONObject.parseObject(resp.body().string().toLowerCase());
            if (jObj.containsKey("rows")) {
                JSONArray rows = (JSONArray)jObj.get("rows");
                if(rows.size()>0){
                    PrintWriter printWriter = new PrintWriter(Utils.Callback.getStdout(), true);
                    printWriter.write(String.format("[+] found one vul: %s",domain));
                }
                return rows.size() > 0;
            }
        } catch (Exception ex) {
            PrintWriter printWriter = new PrintWriter(Utils.Callback.getStderr(), true);
            printWriter.write(String.format("[-] an error has occurred: %s",ex.getMessage()));
            return false;
        }
        return false;
    }

    @Override
    public boolean flushCache() {
        return true;
    }

    @Override
    public boolean flushCache(int count) {
        return flushCache();
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
