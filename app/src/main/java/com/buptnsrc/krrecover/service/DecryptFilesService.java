package com.buptnsrc.krrecover.service;

import android.app.IntentService;
import android.content.Intent;
import android.support.annotation.Nullable;
import android.util.Log;

import com.buptnsrc.krrecover.util.DecryptByLogFileUtil;


public class DecryptFilesService extends IntentService
{

    public DecryptFilesService(){
        super("DecryptFilesService");
    }
    @Override
    protected void onHandleIntent(@Nullable Intent intent)
    {
        Log.i("P-DecryptFilesService", "Start DecryptByLogFileUtil to decrypt.");

        DecryptByLogFileUtil decryptByLogFileUtil = new DecryptByLogFileUtil();
        decryptByLogFileUtil.decryptFiles();
    }






}
