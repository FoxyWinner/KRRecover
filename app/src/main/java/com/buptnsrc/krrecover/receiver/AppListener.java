package com.buptnsrc.krrecover.receiver;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageManager;
import android.os.Parcelable;
import android.util.Log;

import com.buptnsrc.krrecover.modelDetect.AnalysisService;


public class AppListener extends BroadcastReceiver
{
    public AppListener() {
        super();
    }

    @Override
    public void onReceive(Context context, Intent intent)
    {
        ApplicationInfo applicationInfo;
        String action = intent.getAction();
        String packageName = intent.getData().getSchemeSpecificPart();
        PackageManager packageManager = context.getPackageManager();
        Log.i("【P-AppListener】","onReceive");

        //如果包名不是本项目
        if(!packageName.equals("com.buptnsrc.packantiransom") && !packageName.equals("com.buptnsrc.packantiransomchild"))
        {
            // 安装
            if((action.equals("android.intent.action.PACKAGE_ADDED")) || (action.equals("android.intent.action.PACKAGE_REPLACED")))
            {
                SharedPreferences suspiciousSharedPreferences = context.getSharedPreferences("suspiciousList", Context.MODE_WORLD_READABLE+Context.MODE_WORLD_WRITEABLE+Context.MODE_MULTI_PROCESS);
                Boolean isSuspicious = suspiciousSharedPreferences.getBoolean(packageName, false);
                if (!isSuspicious)
                {
                    // 将其加入可疑名单
                    suspiciousSharedPreferences.edit().putBoolean(packageName, true).commit();

                    // 更新可疑计数
                    int count = suspiciousSharedPreferences.getInt("suspiciousCount", 0);
                    count ++;
                    suspiciousSharedPreferences.edit().putInt("suspiciousCount", count).commit();
                    try
                    {
                        applicationInfo = packageManager.getApplicationInfo(packageName, 0);
                    } catch (PackageManager.NameNotFoundException e)
                    {
                        e.printStackTrace();
                        applicationInfo = null;
                    }
                    Log.i("【P-AppListener】","Detect APP installed:"+packageName);

                    // 调用AnalysisService进行检测
                    Intent intentAnalysisService=new Intent(context, AnalysisService.class);
                    intentAnalysisService.putExtra("APPINFO", ((Parcelable)applicationInfo));
                    context.startService(intentAnalysisService);
                }

            }

            // 卸载
            if(action.equals("android.intent.action.PACKAGE_REMOVED"))
            {
                SharedPreferences whiteList = context.getSharedPreferences("whiteList", Context.MODE_WORLD_READABLE+Context.MODE_WORLD_WRITEABLE+Context.MODE_MULTI_PROCESS);
                Boolean isInWhiteList = whiteList.getBoolean(packageName,false);

                if(isInWhiteList)
                {
                    whiteList.edit().remove(packageName).apply();
                }

                SharedPreferences suspiciousList = context.getSharedPreferences("suspiciousList", Context.MODE_WORLD_READABLE+Context.MODE_WORLD_WRITEABLE+Context.MODE_MULTI_PROCESS);
                int suspiciousCount = suspiciousList.getInt("suspiciousCount",0);
                if(suspiciousCount>0)
                {
                    Boolean isSuspicious = suspiciousList.getBoolean(packageName,false);
                    if(isSuspicious)
                    {
                        suspiciousList.edit().remove(packageName).apply();
                        int newCount = suspiciousCount-1;
                        suspiciousList.edit().putInt("suspiciousCount",newCount).apply();
                    }
                }
                suspiciousCount = suspiciousList.getInt("suspiciousCount",0);
                Log.i("【P-AppListener】","Detect APP uninstalled:"+packageName+", "+ suspiciousCount + " now.");
            }
        }

    }
}

