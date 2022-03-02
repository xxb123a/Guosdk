package com.example.web;

import android.text.TextUtils;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;

import okhttp3.Cookie;
import okhttp3.CookieJar;
import okhttp3.HttpUrl;

public class MyCookieJar implements CookieJar {

    private HashMap<String, List<Cookie>> mCookieStore;
    public MyCookieJar(){
        mCookieStore = new HashMap<>();
    }

    @Override
    public void saveFromResponse(HttpUrl url, List<Cookie> cookies) {
        mCookieStore.put(url.host(), cookies);
    }

    @Override
    public List<Cookie> loadForRequest(HttpUrl url) {
        List<Cookie> cookies = mCookieStore.get(url.host());
        return cookies != null ? cookies : new ArrayList<Cookie>();
    }

    public void clearAndSet(String url, String cookieStr) {
        if (TextUtils.isEmpty(url) || TextUtils.isEmpty(cookieStr)) {
            return;
        }
        HttpUrl httpUrl = HttpUrl.parse(url);
        if (httpUrl == null) {
            return;
        }
        String[] cookieArray = cookieStr.split(";");
        List<Cookie> cookies = new ArrayList<>();
        for (String ck : cookieArray) {
            Cookie cookie = Cookie.parse(httpUrl, ck);
            if (cookie == null) {
                continue;
            }
            cookies.add(cookie);
        }
        mCookieStore.clear();
        mCookieStore.put(httpUrl.host(), (cookies.size() != 0) ? Collections.unmodifiableList(cookies)
                : Collections.<Cookie>emptyList());
    }
}

