package com.example.mac.packantiransom;

import android.app.ActivityManager;
import android.app.AlertDialog;
import android.content.ComponentName;
import android.content.Context;
import android.content.DialogInterface;
import android.content.Intent;
import android.content.SharedPreferences;
import android.content.pm.PackageInfo;
import android.os.Bundle;
import android.os.Handler;
import android.os.Message;
import android.os.Parcelable;
import android.support.v7.app.AppCompatActivity;
import android.util.Log;
import android.view.View;
import android.view.WindowManager;
import android.widget.Button;

import com.example.mac.packantiransom.activity.packActivity;
import com.example.mac.packantiransom.modelDetect.AnalysisService;
import com.example.mac.packantiransom.service.decryptFiles;

import java.util.List;


/****
 *  MainActivity.java作为主入口，负责调用以下功能：
 *  1、调用packActivity.java，实现"将子apk设置为系统内置app"的功能
 *  2、
 *
 *
 *（更新于 2019.4.26 by 沈阿娜）
 *
 * */
public class MainActivity extends AppCompatActivity {
    public static Context context;
    Runnable r=null;
    Runnable r_decrypt=null;
    Runnable r_childAPK=null;
    MainHandler mainHandler;
    public MainActivity(){
        super();

    }

    @Override
    protected void onStart() {
        super.onStart();
        context=this;
        Log.i("MainActivity","onStart");
        Intent i=getIntent();
        try {
            String appName=i.getStringExtra("appName");
            if(appName.length()>1){
                window(appName);
            }
        }catch (Exception e){

        }


    }

    @Override
    public void onCreate(Bundle arg2) {
        super.onCreate(arg2);
        setContentView(R.layout.activity_pack);
        context=this;
        mainHandler = new MainHandler();
        Button decrypt=findViewById(R.id.decryptButton);
        decrypt.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                r_decrypt=new Runnable() {
                    // 2.21修改：将以下内容放置到handler中，并利用message来进行消息传达
                    @Override
                    public void run() {
                        Log.i("choseDecrypt","startDecrypt");
                        Message msg4=Message.obtain();
                        msg4.what=4;
                        mainHandler.sendMessage(msg4);
                    }
                };
                new Thread(r_decrypt).start();
            }
        });



        r=new Runnable() {
            // 2.21修改：将以下内容放置到handler中，并利用message来进行消息传达
            @Override
            public void run() {
                Message msg = Message.obtain();
                msg.what = 1; // 消息标识
                msg.obj = "whiteList"; // 消息内存存放
                mainHandler.sendMessage(msg);

                Message msg2 = Message.obtain();
                msg2.what = 2; // 消息标识
                msg2.obj = "suspiciousList"; // 消息内存存放
                mainHandler.sendMessage(msg2);

                Message msg3 = Message.obtain();
                msg3.what = 3; // 消息标识
                msg3.obj = "storeChildAPK"; // 消息内存存放
                mainHandler.sendMessage(msg3);
            }
        };
        new Thread(r).start();

    }


    class MainHandler extends Handler{
        @Override
        public void handleMessage(Message msg) {
            switch (msg.what){
                case 1:
                    /** 获取设备上已安装应用，建立白名单**/
                    SharedPreferences readWhite = getSharedPreferences("whiteList", MODE_WORLD_READABLE+MODE_WORLD_WRITEABLE+MODE_MULTI_PROCESS);
                    //步骤2：获取文件中的值
                    if(!readWhite.getBoolean("hasSet",false)){
                        SharedPreferences.Editor editor=readWhite.edit();
                        /** 获取设备上已安装应用**/
                        List<PackageInfo> packages = getPackageManager().getInstalledPackages(0);
                        String packageName;
                        for(int i=0;i<packages.size();i++) {
                            PackageInfo packageInfo = packages.get(i);
                            packageName = packageInfo.packageName;
                            editor.putBoolean(packageName,true);
                        }
                        editor.putBoolean("com.example.mac.test1",true);
                        editor.putBoolean("com.example.mac.packantiransom",true);
                        editor.putBoolean("com.google.android.gms.persistent",true);
                        editor.putBoolean("com.google.process.gapps",true);
                        editor.putBoolean("io.va.exposed:x",true);
                        editor.putBoolean("io.va.exposed",true);
                        editor.putBoolean("com.google.android.googlequicksearchbox:search",true);
                        editor.putBoolean("system",true);
                        editor.putBoolean("com.google.android.music:main",true);

                        editor.putBoolean("hasSet",true);
                        editor.apply();
                    }
                    break;
                case 2:
                    /** 可疑名单 **/
                    SharedPreferences readSuspicious = getSharedPreferences("suspiciousList", MODE_WORLD_READABLE+MODE_WORLD_WRITEABLE+MODE_MULTI_PROCESS);
                    int suspiciousCount=readSuspicious.getInt("suspiciousCount",0);
                    if(suspiciousCount==0){
                        readSuspicious.edit().putInt("suspiciousCount",0).apply();
                    }
                    if(suspiciousCount>0){
//                        ActivityManager am = (ActivityManager) context.getSystemService(Context.ACTIVITY_SERVICE);
//                        List<ActivityManager.RunningServiceInfo> serviceInfos = am.getRunningServices(20);
//                        if (serviceInfos != null) {
//                            for (ActivityManager.RunningServiceInfo serviceInfo : serviceInfos) {
//                                String prcName = serviceInfo.process;
//                                if(prcName.equals("com.example.mac.test1")){
                        ActivityManager activityManager = (ActivityManager) context.getSystemService(Context.ACTIVITY_SERVICE);
                        List<ActivityManager.RunningServiceInfo> serviceList = activityManager.getRunningServices(Integer.MAX_VALUE);
                        for (int i = 0; i < serviceList.size(); i++) {
                            ActivityManager.RunningServiceInfo serviceInfo = serviceList.get(i);
                            ComponentName serviceName = serviceInfo.service;
                            if (serviceName.getClassName().equals("com.example.mac.test1.BackServer")) {
//                                    Intent stopIntent = new Intent(this,"com.example.mac.test1");
////                                    stopIntent.setPackage("com.example.mac.test1");
//                                    stopService(stopIntent);
                                    ComponentName componentName=new ComponentName("com.example.mac.test1","com.example.mac.test1.BackServer");
                                    Intent startIntent=new Intent();
                                    startIntent.setAction("android.intent.action.RESPOND_VIA_MESSAGE");
                                    startIntent.setComponent(componentName);
                                    stopService(startIntent);
                                }
                            }

                        Log.i("lala_MainActivity", "start BackServer");
//                        Intent startIntent = new Intent("com.example.mac.startBackServer");
//                        startIntent.setPackage("com.example.mac.test1");
                        ComponentName componentName=new ComponentName("com.example.mac.test1","com.example.mac.test1.BackServer");
                        Intent startIntent=new Intent();
                        startIntent.setAction("android.intent.action.RESPOND_VIA_MESSAGE");
                        startIntent.setComponent(componentName);
                        startService(startIntent);
                        Log.i("lala_MainActivity", "end BackServer");
                    }
                    break;
                case 3:
                    SharedPreferences ReadWhite = getSharedPreferences("whiteList", MODE_WORLD_READABLE+MODE_WORLD_WRITEABLE+MODE_MULTI_PROCESS);
                    //步骤2：获取文件中的值
                    if(!ReadWhite.getBoolean("storeChileAPK",false)){
                        SharedPreferences.Editor editor=ReadWhite.edit();
                        editor.putBoolean("storeChileAPK",true);
                        editor.apply();
                        Intent startPackActivity=new Intent(context,packActivity.class);
                        startActivity(startPackActivity);
                    }
                    break;
                case 4:
                    Log.i("Lable","start decryptFiles");
                    Intent startDecyptService=new Intent(context,decryptFiles.class);
                    startService(startDecyptService);
//                    LogUtil lu=new LogUtil();
//                    lu.dealLog();
                    break;

            }
        }
    }

    @Override
    protected void onDestroy() {
        if(r==null){
        }else {
            mainHandler.removeCallbacks(r);
        }
        if(r_decrypt==null){
        }else {
            mainHandler.removeCallbacks(r_decrypt);
        }
        super.onDestroy();
    }

    public static void window(final String appName){


                Log.i("here~","startAlertWindow");
                String message= "新安装应用<"+appName+">疑似勒索软件！您可选择手动将其加入以下名单。若您选择白名单，您将失去我们提供的守护。";
                android.app.AlertDialog.Builder builder = new AlertDialog.Builder(context);//只有activity才能使用window
                builder.setTitle("警告！");
                builder.setMessage(message);
//        builder.setIcon(R.mipmap.ic_launcher);
                builder.setPositiveButton("可疑名单", new DialogInterface.OnClickListener() {//添加"Yes"按钮
                    @Override
                    public void onClick(DialogInterface dialogInterface, int i) {
                        // 先啥也不干
                    }
                });
                builder.setNegativeButton("白名单", new DialogInterface.OnClickListener() {//添加取消
                    @Override
                    public void onClick(DialogInterface dialogInterface, int i) {
                        // 先啥也不干
                    }
                });
                builder.setNeutralButton("默认", new DialogInterface.OnClickListener() {//添加普通按钮
                    @Override
                    public void onClick(DialogInterface dialogInterface, int i) {
                        // 先啥也不干
                    }
                });
//                builder.show();
                AlertDialog dialog =builder.create();
                dialog.getWindow().setType(WindowManager.LayoutParams.TYPE_TOAST);
                dialog.show();


    }

}
