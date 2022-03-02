package com.example.web;

import android.annotation.SuppressLint;
import android.content.Context;
import android.net.Uri;
import android.os.Build;
import android.text.TextUtils;
import android.util.AttributeSet;
import android.webkit.CookieManager;
import android.webkit.JavascriptInterface;
import android.webkit.WebResourceRequest;
import android.webkit.WebResourceResponse;
import android.webkit.WebSettings;
import android.webkit.WebView;
import android.webkit.WebViewClient;

import com.example.customokhttp311.MainActivity;
import com.example.customokhttp311.PreferredCipherSuiteSSLSocketFactory;
import com.example.customokhttp311.TrustAllManager;

import org.json.JSONObject;

import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.Method;
import java.security.KeyStore;
import java.security.Security;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.zip.Inflater;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.X509TrustManager;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.annotation.RequiresApi;
import okhttp3.CookieJar;
import okhttp3.Headers;
import okhttp3.MediaType;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.RequestBody;
import okhttp3.Response;
import okhttp3.ResponseBody;
import okhttp3.internal.http.HttpHeaders;
import okhttp3.internal.http.HttpMethod;
import okhttp3.internal.http.RealResponseBody;
import okio.GzipSource;
import okio.InflaterSource;
import okio.Okio;

public class CustomWebView extends WebView {
    private OkHttpClient mOkhttpClient;
    private String body;
    private String method;

    public CustomWebView(@NonNull Context context) {
        this(context, null);
    }

    public CustomWebView(@NonNull Context context, @Nullable AttributeSet attrs) {
        super(context, attrs);
        initOkhttp();
        initConfig();
        setWebViewClient(new WebViewClient() {
            @Override
            public boolean shouldOverrideUrlLoading(WebView view, String url) {
                view.loadUrl(url);
                return true;
            }

            @RequiresApi(api = Build.VERSION_CODES.LOLLIPOP)
            @Nullable
            @Override
            public WebResourceResponse shouldInterceptRequest(WebView view, WebResourceRequest request) {
                String url = request.getUrl().toString();
                if (url.startsWith("http://") || url.startsWith("https://")) {
                    syncCookie(url);
                    Request.Builder builder = new Request.Builder().url(url);
                    RequestBody requestBody = null;
                    try {
                        if (HttpMethod.requiresRequestBody(request.getMethod())) {

                            requestBody = RequestBody.create(MediaType.parse(""), "");
                        }
                        builder.method(request.getMethod(), requestBody);
                    } catch (Throwable e) {
                    }
                    dealWithOriginHeader(builder, request);
                    String rawMethod = request.getMethod();
                    Uri uri = Uri.parse(url);
                    String path = uri.getPath();
                    String host = uri.getHost();
                    int port = uri.getPort();
                    if (!TextUtils.isEmpty(body)) {
                        System.out.println("this is body ------------" + body);
                        try {
                            createAjaxRequest(builder, rawMethod, url);
                        } catch (Exception e) {

                        }
                        body = null;
                    }

                    Request proxyRequest = builder.build();

                    try {
                        Response execute = mOkhttpClient.newCall(proxyRequest).execute();
                        Response response = checkUnzipResponse(execute);

                        ResponseBody body = response.body();
                        String charset = "UTF-8";
                        String contentType = "Content-Type";
                        String type = response.header(contentType);

//                        if (response.isRedirect()) {
//                            return webRedirect(url, response, type, charset);
//                        }
                        int code = response.code();
                        String msg = response.message();
                        if (TextUtils.isEmpty(msg)) {
                            msg = "OK";
                        }
                        if (response.code() >= 400) {
                            return null;
                        }
                        if (null == body) {
                            if ("options".equalsIgnoreCase(rawMethod)) {
                                Map<String, String> headersMap = okHeaders2WebviewHeaders(url, response.headers());
                                return new WebResourceResponse(type, charset, code, msg, headersMap, null);
                            }
                            return null;
                        }
                        byte[] bodyBytes = body.bytes();
                        if (bodyBytes.length == 0) {
                            return null;
                        }
                        try {
                            charset = body.contentType().charset().displayName();
                            type = body.contentType().toString();
                        } catch (NullPointerException e) {
                            // content type not identify
                        }

                        type = getType(type, bodyBytes);
                        byte[] pageContents = addHeaderProxy(bodyBytes, type, charset);
                        String pc = new String(pageContents);
                        InputStream isContents = new ByteArrayInputStream(pageContents);
                        if (type.contains("text/html")) {
                            type = "text/html";
                        }
                        Map<String, String> webviewHeaders = okHeaders2WebviewHeaders(url, response.headers());
                        return new WebResourceResponse(type, charset, code, msg, webviewHeaders, isContents);
                    } catch (final Throwable throwable) {

                    }
                }
                return super.shouldInterceptRequest(view, request);
            }
        });
    }
    private String mProxyStr = "";
    private byte[] addHeaderProxy(byte[] pageContents, String type, String charset) {
        String html = "text/html";
        if(type.equals(html)){
            if(TextUtils.isEmpty(mProxyStr)){
                //
                mProxyStr = readProxyStr();
            }
            if(!TextUtils.isEmpty(mProxyStr))
            {
                String content = new String(pageContents);
                String headHtml = "<head>";
                int index = content.indexOf(headHtml);
                if(index >= 0){
                    String prefix = content.substring(0,index+headHtml.length());
                    String suffix = content.substring(index+headHtml.length());
                    return (prefix + mProxyStr + suffix).getBytes();
                }
                return (mProxyStr+new String(pageContents)).getBytes();
            }
        }
        return pageContents;
    }

    private String readProxyStr(){
        try {
            InputStream fis = getContext().getAssets().open("temp.txt");
            byte[] bytes = new byte[fis.available()];
            fis.read(bytes);
            fis.close();
            return new String(bytes);
        } catch (IOException e) {
            e.printStackTrace();
        }
        return "";
    }

    private void initOkhttp() {
        Security.addProvider(new cn.gmssl.jsse.provider.GMJSSE());
        Security.addProvider(new cn.gmssl.jce.provider.GMJCE());
        OkHttpClient.Builder builder = new OkHttpClient.Builder();
        X509TrustManager manager = new TrustAllManager();
        SSLSocketFactory factory = null;
        try {
            factory = createSocketFactory(null, null);
        } catch (Exception e) {
            e.printStackTrace();
        }
        SSLSocketFactory factory2 = new PreferredCipherSuiteSSLSocketFactory(factory);
        builder.sslSocketFactory(factory2, manager);
        builder.hostnameVerifier((hostname, session) -> true);
        builder.cookieJar(new MyCookieJar());
        mOkhttpClient = builder.build();
    }


    public void createAjaxRequest(Request.Builder builder, String rawMethod, String url) throws Exception {
        RequestBody requestBody = null;
        // 针对post，添加body体
        String method = rawMethod;
        String post = "post";
        if (method.equalsIgnoreCase(post)) {
            // body结构构造
            String body = this.body;
            String str = "application/x-www-form-urlencoded";
            if (TextUtils.isEmpty(body)) {
                str = "";
            }
//            requestBody = RequestBody.create(MediaType.parse(str), body);
            requestBody = RequestBody.create(MediaType.parse(str), body);
        }
        if (HttpMethod.requiresRequestBody(rawMethod) && requestBody == null) {
            requestBody = RequestBody.create(MediaType.parse("application/x-www-form-urlencoded"), "");
        }
        builder.method(rawMethod, requestBody);
    }

    public static SSLSocketFactory createSocketFactory(KeyStore kepair, char[] pwd) throws Exception {
        TrustAllManager[] trust = {new TrustAllManager()};

        KeyManager[] kms = null;
        if (kepair != null) {
            KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
            kmf.init(kepair, pwd);
            kms = kmf.getKeyManagers();
        }

        SSLContext ctx = SSLContext.getInstance("GMSSLv1.1", "GMJSSE");
        java.security.SecureRandom secureRandom = new java.security.SecureRandom();
        ctx.init(kms, trust, secureRandom);

        ctx.getServerSessionContext().setSessionCacheSize(8192);
        ctx.getServerSessionContext().setSessionTimeout(3600);

        SSLSocketFactory factory = ctx.getSocketFactory();
        return factory;
    }


    private Map<String, String> okHeaders2WebviewHeaders(String url, Headers headers) {
        Map<String, String> webviewHeaders = new HashMap<>();
        Map<String, List<String>> rMultiHeaders = headers.toMultimap();
        for (String k : rMultiHeaders.keySet()) {
            List<String> values = rMultiHeaders.get(k);
            if (values != null) {
                StringBuilder buffer = new StringBuilder();
                for (int i = 0; i < values.size(); i++) {
                    if (i > 0) {
                        buffer.append(";");
                    }
                    buffer.append(values.get(i));
                    if ("Set-Cookie".equalsIgnoreCase(k)) {
                        CookieManager.getInstance().setCookie(url, values.get(i));
                    }
                }
                webviewHeaders.put(headerParse(k), buffer.toString());
            }
        }
        return webviewHeaders;
    }

    public String getType(String type, byte[] bytes) {
        String mType = type;
        if (TextUtils.isEmpty(type)) {
            String plain = "text/plain";
            mType = plain;
        }
        String html = "text/html";
        String trim = new String(bytes).trim();
        boolean likeHtml = trim.startsWith("<");
        if (!likeHtml && trim.length() > 10) {
            String subtrim = trim.substring(0, 10);
            if ((int) (subtrim.charAt(0)) == 65279) {
                subtrim = subtrim.replace(subtrim.charAt(0) + "", "");
                likeHtml = subtrim.startsWith("<");
            }
        }
        if (type.contains(html) && likeHtml) {
            mType = html;
        }
        return mType;
    }

    @RequiresApi(api = Build.VERSION_CODES.LOLLIPOP)
    private void dealWithOriginHeader(Request.Builder builder, WebResourceRequest request) {
        Map<String, String> requestHeaders = request.getRequestHeaders();
        Set<String> keys = requestHeaders.keySet();
        for (String key : keys) {
            String h = requestHeaders.get(key);
            builder.header(headerParse(key), h);
        }
    }

    public static String headerParse(String header) {
        if (TextUtils.isEmpty(header)) {
            return "";
        }
        String lower = header.toLowerCase();
        switch (lower) {
            case "te":
                return "TE";
            case "tcn":
                return "TCN";
            case "last-event-id":
                return "Last-Event-ID";
            case "dnt":
                return "DNT";
            case "content-md5":
                return "Content-MD5";
            case "accept-ch":
                return "Accept-CH";
            default:
                break;
        }

        try {
            String[] split = header.split("-");
            for (int i = 0; i < split.length; i++) {
                char[] cs = split[i].toCharArray();
                if (cs[0] >= 97 && cs[0] <= 122) {
                    cs[0] -= 32;
                }
                split[i] = String.valueOf(cs);
            }
            StringBuilder rst = new StringBuilder(split[0]);
            for (int i = 1; i < split.length; i++) {
                rst.append("-").append(split[i]);
            }
            return rst.toString();
        } catch (Throwable throwable) {
        }
        return header;
    }

    private void syncCookie(String url) {
        try {
            CookieManager.getInstance().removeExpiredCookie();
            String cookie = CookieManager.getInstance().getCookie(url);
            CookieJar cookieJar = mOkhttpClient.cookieJar();
            if (cookieJar instanceof MyCookieJar) {
                ((MyCookieJar) cookieJar).clearAndSet(url, cookie);
            }
        } catch (Throwable throwable) {
        }
    }


    @SuppressLint({"SetJavaScriptEnabled", "JavascriptInterface"})
    private void initConfig() {
        WebSettings settings = getSettings();
        settings.setJavaScriptEnabled(true);
        settings.setCacheMode(WebSettings.LOAD_NO_CACHE);
        settings.setAllowFileAccess(true);
        settings.setUserAgentString(settings.getUserAgentString().replace("wv", ""));
        settings.setLoadWithOverviewMode(true);
        settings.setJavaScriptCanOpenWindowsAutomatically(true);
        settings.setDatabaseEnabled(true);
        settings.setDomStorageEnabled(true);
        settings.setAllowContentAccess(true);
        settings.setAllowFileAccessFromFileURLs(false);
        settings.setAllowUniversalAccessFromFileURLs(true);
        settings.setBlockNetworkImage(false);
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP) {
            CookieManager.getInstance().setAcceptThirdPartyCookies(this, true);
        }

        setMixContent(this);
        addJavascriptInterface(this, "interception");
    }

    @JavascriptInterface
    public void customAjax(String requestId, String body) {
        System.out.println("customAjax    -----------------------" + body);
        this.method = requestId;
        this.body = body;
    }
    @JavascriptInterface
    public void customSubmit(String json) {
        System.out.println("customAjax    -----------------------" + body);
        this.body = body;
    }

    public static Response checkUnzipResponse(Response networkResponse) {
        try {
            Response.Builder responseBuilder = networkResponse.newBuilder();
            if ("gzip".equalsIgnoreCase(networkResponse.header("Content-Encoding"))
                    && HttpHeaders.hasBody(networkResponse)) {
                GzipSource responseBody = new GzipSource(networkResponse.body().source());
                Headers strippedHeaders = networkResponse.headers().newBuilder()
                        .removeAll("Content-Encoding")
                        .removeAll("Content-Length")
                        .build();
                responseBuilder.headers(strippedHeaders);
                String contentType = networkResponse.header("Content-Type");
                responseBuilder.body(new RealResponseBody(contentType, -1L, Okio.buffer(responseBody)));
            } else if ("deflate".equalsIgnoreCase(networkResponse.header("Content-Encoding"))
                    && HttpHeaders.hasBody(networkResponse)) {
                InflaterSource inflaterSource = new InflaterSource(networkResponse.body().source(), new Inflater(true));
                Headers strippedHeaders = networkResponse.headers().newBuilder()
                        .removeAll("Content-Encoding")
                        .removeAll("Content-Length")
                        .build();
                responseBuilder.headers(strippedHeaders);
                String contentType = networkResponse.header("Content-Type");
                responseBuilder.body(new RealResponseBody(contentType, -1L, Okio.buffer(inflaterSource)));
            }
            return responseBuilder.build();
        } catch (Throwable e) {
        }

        return networkResponse;
    }

    private static void setMixContent(WebView webView) {

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP) {
            webView.getSettings().setMixedContentMode(WebSettings.MIXED_CONTENT_ALWAYS_ALLOW);
        }

        try {
            Method m = WebSettings.class.getMethod("setMixedContentMode", int.class);
            // 0 = MIXED_CONTENT_ALWAYS_ALLOW
            m.invoke(webView.getSettings(), 0);
        } catch (Throwable ex) {
        }
    }
}
