package com.example.mac.packantiransom.modelDetect;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageManager;
import android.os.Parcelable;
import android.util.Log;


import com.example.mac.packantiransom.MainActivity;

import static android.content.Context.MODE_PRIVATE;

public class AppListener extends BroadcastReceiver {
    public AppListener() {
        super();
    }

    public void onReceive(Context arg9, Intent arg10) {
        ApplicationInfo v2_1;
        String v0 = arg10.getAction();
        String v1 = arg10.getData().getSchemeSpecificPart();//v1已经是packageName了
        PackageManager v2 = arg9.getPackageManager();
        String packageName =v1;
        Log.i("AppListener","onReceive");
        if(!packageName.equals("com.example.mac.packantiransom") && !packageName.equals("com.example.mac.test1")){
            if((v0.equals("android.intent.action.PACKAGE_ADDED")) || (v0.equals("android.intent.action.PACKAGE_REPLACED"))) {

                SharedPreferences readSuspicious = arg9.getSharedPreferences("suspiciousList", Context.MODE_WORLD_READABLE+Context.MODE_WORLD_WRITEABLE+Context.MODE_MULTI_PROCESS);
                if (!readSuspicious.getBoolean(packageName, false)) {
//                    Intent main=new Intent(arg9, MainActivity.class);
//                    main.setFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
//                    arg9.startActivity(main);

                    readSuspicious.edit().putBoolean(packageName, true).commit();
                    int count = readSuspicious.getInt("suspiciousCount", 0);
                    count = count + 1;
                    readSuspicious.edit().putInt("suspiciousCount", count).commit();
                    try {
                        v2_1 = v2.getApplicationInfo(v1, 0);
                    } catch (PackageManager.NameNotFoundException e) {
                        e.printStackTrace();
                        v2_1 = null;
                    }
                    Log.i("new APP installed:",packageName);
//                    Intent v4_1 = new Intent(arg9, MainActivity.class);
//                    v4_1.setFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
//                    v4_1.putExtra("APPINFO", ((Parcelable)v2_1));
//                    arg9.startActivity(v4_1);
                    Intent v4_1=new Intent(arg9,AnalysisService.class);
                    v4_1.putExtra("APPINFO", ((Parcelable)v2_1));
                    arg9.startService(v4_1);
                }

            }

            if(v0.equals("android.intent.action.PACKAGE_REMOVED")) {
                SharedPreferences readWhite = arg9.getSharedPreferences("whiteList", Context.MODE_WORLD_READABLE+Context.MODE_WORLD_WRITEABLE+Context.MODE_MULTI_PROCESS);
                if(readWhite.getBoolean(packageName,false)){
                    readWhite.edit().remove(packageName).apply();
                }

                SharedPreferences readSuspicious = arg9.getSharedPreferences("suspiciousList", Context.MODE_WORLD_READABLE+Context.MODE_WORLD_WRITEABLE+Context.MODE_MULTI_PROCESS);
                int suspiciousCount=readSuspicious.getInt("suspiciousCount",0);
                if(suspiciousCount>0){
                    if(readSuspicious.getBoolean(packageName,false)){
                        readSuspicious.edit().remove(packageName).apply();
                        int newCount=suspiciousCount-1;
                        readSuspicious.edit().putInt("suspiciousCount",newCount).apply();
                    }
                }
            }
        }

    }
}

