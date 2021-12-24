package burp.utils;

public class HttpHeader {
    public String name;
    public String value = "";

    public HttpHeader(String src) {
        int headerLength = src.indexOf(':');
        if (headerLength > -1) {
            name = src.substring(0, headerLength);
            value = src.substring(headerLength + 1).trim();
        } else {
            name = src;
        }
    }

    @Override
    public String toString() {
        return String.format("%s: %s", name, value);
    }
}
