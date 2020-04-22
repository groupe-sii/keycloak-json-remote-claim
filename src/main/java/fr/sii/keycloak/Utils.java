package fr.sii.keycloak;

import java.net.URLEncoder;
import java.net.http.HttpRequest;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;

class Utils {

    static Map<String, String> buildMapFromStringConfig(String config) {
        final Map<String, String> map = new HashMap<>();

        //FIXME: using MULTIVALUED_STRING_TYPE would be better but it doesn't seem to work
        if (config != null && !"".equals(config.trim())) {
            String[] configList = config.trim().split("&");
            String[] keyValue;
            for (String configEntry : configList) {
                keyValue = configEntry.split("=", 2);
                if (keyValue.length == 2) {
                    map.put(keyValue[0], keyValue[1]);
                }
            }
        }

        return map;
    }

    static HttpRequest.BodyPublisher getFormData(Map<String, String> data) {
        StringBuilder builder = new StringBuilder();
        data.forEach((key, value) -> {
            if (builder.length() > 0) {
                builder.append("&");
            }
            builder.append(URLEncoder.encode(key, StandardCharsets.UTF_8));
            builder.append("=");
            builder.append(URLEncoder.encode(value, StandardCharsets.UTF_8));
        });
        return HttpRequest.BodyPublishers.ofString(builder.toString());
    }
}
