package com.example.web;

import android.os.Bundle;
import android.webkit.WebView;

import com.example.customokhttp311.R;

import androidx.annotation.Nullable;
import androidx.appcompat.app.AppCompatActivity;

public class WebActivity extends AppCompatActivity {
    @Override
    protected void onCreate(@Nullable Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_web);
        WebView webView = findViewById(R.id.my_webview);
//        webView.loadUrl("https://demo.gmssl.cn:443/");
        webView.loadUrl("https://demo.gmssl.cn/1.jsp");
    }
}
