package com.example.customokhttp311;

import androidx.appcompat.app.AppCompatActivity;

import android.os.Bundle;
import android.os.Handler;
import android.os.Message;
import android.util.Log;
import android.view.View;
import android.widget.TextView;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.UnknownHostException;
import java.security.KeyStore;
import java.security.Provider;
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.X509TrustManager;

//import cn.gmssl.security.util.DisabledAlgorithmConstraints;
import okhttp3.Call;
import okhttp3.Callback;
import okhttp3.CipherSuite;
import okhttp3.ConnectionSpec;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;

public class MainActivity extends AppCompatActivity {
    public Handler mHandler = null;
    public TextView mTextView = null;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        mTextView = findViewById(R.id.textView);
        mHandler = new Handler(){
            @Override
            public void handleMessage(android.os.Message msg){
                Bundle b = msg.getData();
                String message = b.getString("response");
                message += "\r\n";
                mTextView.append(message);
            }
        };
    }

    private void sendMessageText(String messageText){
        Message msg = new Message();
        Bundle b = new Bundle();
        b.putString("response",messageText);
        msg.what = 1;
        msg.setData(b);
        mHandler.sendMessage(msg);
    }

    void testDns(String addr,int port) {
        try {
            System.out.println("DNS test(" + addr + ")...");
            System.out.println("IP=" + InetAddress.getByName(addr));
            System.out.println("TCP test(" + addr + ":" + port + ")...");
            Socket sock = new Socket();
            sock.connect(new InetSocketAddress(addr, port), 5000);
            sock.close();
            System.out.println("TCP test OK.");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private void request() {
        try {
            //Security.insertProviderAt((Provider) Class.forName("cn.gmssl.jce.provider.GMJCE").newInstance(), 1);
            //Security.insertProviderAt((Provider) Class.forName("cn.gmssl.jsse.provider.GMJSSE").newInstance(), 2);

            new Thread(new Runnable() {
                @Override
                public void run() {
                    testDns("demo.gmssl.cn",443);
                    testDns("gmssl.ymbank.com",4443);
                }
            }).start();

            Security.addProvider(new cn.gmssl.jsse.provider.GMJSSE());
            Security.addProvider(new cn.gmssl.jce.provider.GMJCE());

            sendMessageText("插入密码提供者：insertProviderAt((Provider) Class.forName(cn.gmssl.jce.provider.GMJCE)");
            sendMessageText("插入密码提供者：insertProviderAt((Provider) Class.forName(cn.gmssl.jsse.provider.GMJSSE)");
            Provider[] providers = Security.getProviders();
            for (Provider provider : providers) {
                Log.d("lpftag","provider:"+provider.getName());
                //sendMessageText("\tprovider:"+provider.getName());
            }
            sendMessageText("*********************测试开始*********************");
            OkHttpClient.Builder builder = new OkHttpClient.Builder();
            sendMessageText("创建 OkHttpClient.Builder 对象");
            X509TrustManager manager = new TrustAllManager();
            SSLSocketFactory factory = createSocketFactory(null,null);
            sendMessageText("创建SSLSocketFactory对象");
            SSLSocketFactory factory2 = new PreferredCipherSuiteSSLSocketFactory(factory);
            sendMessageText("创建PreferredCipherSuiteSSLSocketFactory对象");
            builder.sslSocketFactory( factory2, manager);
            builder.hostnameVerifier(new HostnameVerifier() {
                @Override
                public boolean verify(String hostname, SSLSession session) {
                    return true;
                }
            });

            // https://182.92.224.3
            // https://demo.gmssl.cn

            OkHttpClient client = builder.build();
            sendMessageText("创建OkHttpClient对象");
            Request request = new Request.Builder().url("https://gmssl.ymbank.com:4443/mobile/web.html").build();//demo.gmssl.cn网站
            sendMessageText("开始访问https://demo.gmssl.cn地址");
            client.newCall(request).enqueue(new Callback() {
                @Override
                public void onFailure(Call call, IOException e) {
                    e.printStackTrace();
                    Log.d("lpftag","失败了");
                    sendMessageText("Version："+okhttp3.internal.Version.userAgent());
                    sendMessageText("失败了,异常原因："+e.toString());
                    sendMessageText("访问https://demo.gmssl.cn结束");
                    sendMessageText("*********************测试结束*********************");
                }
                @Override
                public void onResponse(Call call, Response response) throws IOException {
                    Log.d("lpftag","成功了，response = "+response);
                    sendMessageText("Version："+okhttp3.internal.Version.userAgent());
                    sendMessageText("成功了，response = "+response.toString());
                    sendMessageText("访问https://demo.gmssl.cn结束");
                    sendMessageText("*********************测试结束*********************");
                }
            });
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void request(View view) {
        request();
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
}
