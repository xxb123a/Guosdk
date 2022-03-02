package com.example.customokhttp311;

import android.app.Application;

import java.security.Security;

public class MyApplication extends Application {

    @Override
    public void onCreate() {
        super.onCreate();
        /*Security.insertProviderAt(new cn.gmssl.jce.provider.GMJCE(), 1);
        Security.insertProviderAt(new cn.gmssl.jsse.provider.GMJSSE(), 2);*/
    }
}
