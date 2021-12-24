package burp.utils;

import burp.IHttpRequestResponse;
import burp.IParameter;

/**
 * @author P1n93r
 */
public class ScanItem {
    public ScanItem(boolean isHeader,String info,IHttpRequestResponse response) {
        this.isHeader = isHeader;
        this.tmpResponse = response;
        this.info = info;
    }
    public boolean isHeader;
    public String info;
    public IHttpRequestResponse tmpResponse;
}
