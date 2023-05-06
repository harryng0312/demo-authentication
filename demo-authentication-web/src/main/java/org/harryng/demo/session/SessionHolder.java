package org.harryng.demo.session;

import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

public class SessionHolder {
    private static Map<String, Map<String, Object>> sessionMap = new ConcurrentHashMap<>();

    public static final String K_USER = "user";
    public static final String K_AUTH_INFO = "authInfo";

    protected static Map<String, Map<String, Object>> getSessionMap() {
        return sessionMap;
    }

    public static Map<String, Object> getSession(String key, boolean created) {
        if (created && getSessionMap().get(key) == null) {
            getSessionMap().put(key, new HashMap<>());
        }
        return getSessionMap().get(key);
    }

    public static Map<String, Object> getSession(String key) {
        return getSession(key, true);
    }
}
