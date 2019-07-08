package com.example.mac.packantiransom.service;

import android.app.IntentService;
import android.content.Intent;
import android.support.annotation.Nullable;
import android.util.Log;

import com.example.mac.packantiransom.Util.LogFileUtil;


public class decryptFiles extends IntentService{

    public decryptFiles(){
        super("decryptFiles");
    }
    @Override
    protected void onHandleIntent(@Nullable Intent intent) {
//        LogUtil lu=new LogUtil();
//        lu.dealLog();
        LogFileUtil lfu=new LogFileUtil();
        lfu.decryptFiles();
//        lfu.decryptOrNot();
    }






}
