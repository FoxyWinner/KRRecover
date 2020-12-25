package com.buptnsrc.krrecover.activity;

import android.app.ActivityManager;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.content.pm.PackageInfo;
import android.os.Bundle;
import android.os.Handler;
import android.os.Message;
import android.support.v7.app.AppCompatActivity;
import android.util.Log;
import android.view.View;
import android.widget.Button;

import com.buptnsrc.krrecover.R;
import com.buptnsrc.krrecover.enums.ChildAPKStatusEnum;
import com.buptnsrc.krrecover.enums.GlobalEnum;
import com.buptnsrc.krrecover.service.DecryptFilesService;

import java.util.List;


/****
 *  ParentActivity.java作为父APK主入口，负责调用以下功能：
 *  1、调用installActivity，实现"将子apk设置为系统内置app"的功能
 *  2、
 *
 *
 *（更新于 2019.4.26 by 沈阿娜）
 *（更新于 2020.6.6 by 侯俊杰）
 * */
public class ParentActivity extends AppCompatActivity
{
    private static final String TAG = "P-ParentActivity";

    public static Context context;
    private Runnable sendMsg2InitThread = null;// 发送消息以初始化白名单、黑名单、安装与设置子APK
    private Runnable decryptThread = null;

    private Button decryptButton;
    private Button skipButton;
    private Button backServerButton;
    private Button checkButton;

    MyHandler myHandler;

    public ParentActivity()
    {
        super();
    }

    @Override
    protected void onStart()
    {
        super.onStart();
        context = this;

        // todo 这段话似乎无意义，待删除
        Log.i("P-ParentActivity", "onStart");
        Intent intent = getIntent();
        try
        {
            String appName = intent.getStringExtra("appName");
            if (appName.length() > 1)
            {
//                window(appName);
            }
        } catch (Exception e)
        {

        }


    }

    @Override
    public void onCreate(Bundle savedInstanceState)
    {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_pack);
        context = this;
        myHandler = new MyHandler();
        decryptButton = findViewById(R.id.decryptButton);
        skipButton = findViewById(R.id.skipBtn);
        backServerButton = findViewById(R.id.btnBackServer);
        checkButton = findViewById(R.id.btn_check);


        decryptButton.setOnClickListener(new View.OnClickListener()
        {
            @Override
            public void onClick(View v)
            {
                decryptThread = new Runnable()
                {
                    // 2.21修改：将以下内容放置到handler中，并利用message来进行消息传达
                    @Override
                    public void run()
                    {
                        Log.i("P-ParentActivity", "startDecryptService");

                        Message msg4 = Message.obtain();
                        // what用于handler接收时辨认消息
                        msg4.what = 4;
                        myHandler.sendMessage(msg4);
                    }
                };

                new Thread(decryptThread).start();
            }
        });

        skipButton.setOnClickListener(new View.OnClickListener()
        {
            @Override
            public void onClick(View v)
            {
                Intent intent = new Intent();
                ComponentName componentName = new ComponentName(GlobalEnum.SUBAPP_PACKAGENAME.getString(), GlobalEnum.SUBAPP_PACKAGENAME.getString() + ".activity.ChildActivity");
                intent.setComponent(componentName);
                startActivity(intent);
                Log.i("【P-ParentActivity】", "Start ChildActivity.");
            }
        });

        backServerButton.setOnClickListener(new View.OnClickListener()
        {
            @Override
            public void onClick(View v)
            {
                Log.i("P-ParentActivity", "Start BackServer.");

                ComponentName componentName = new ComponentName(GlobalEnum.SUBAPP_PACKAGENAME.getString(), GlobalEnum.SUBAPP_PACKAGENAME.getString() + ".activity.ChildActivity");
                Intent startIntent = new Intent();
                startIntent.setAction("android.intent.action.RESPOND_VIA_MESSAGE");
                startIntent.setComponent(componentName);
                startService(startIntent);
                Log.i("P-ParentActivity", "End start BackServer.");
            }
        });

        checkButton.setOnClickListener(new View.OnClickListener()
        {
            @Override
            public void onClick(View v)
            {
                ActivityManager activityManager = (ActivityManager) context.getSystemService(Context.ACTIVITY_SERVICE);
                List<ActivityManager.RunningServiceInfo> serviceList = activityManager.getRunningServices(Integer.MAX_VALUE);
                Log.i("【P-ParentActivity】", "当前运行service：\n");
                for (int i = 0; i < serviceList.size(); i++)
                {
                    ActivityManager.RunningServiceInfo serviceInfo = serviceList.get(i);
                    ComponentName serviceName = serviceInfo.service;
                    Log.i("【P-ParentActivity】", serviceName + "\n");

                    if (serviceName.getClassName().equals("com.buptnsrc.packantiransomchild.service.BackServer"))
                    {
                        Log.i("【P-ParentActivity】", "BackServer正在运行。");
                    }
                }
                Log.i("【P-ParentActivity】", "验证结束");
            }
        });


        sendMsg2InitThread = new Runnable()
        {
            // 2.21修改：将以下内容放置到handler中，并利用message来进行消息传达
            @Override
            public void run()
            {
                // 发送消息：初始化白名单
                Message initWhiteListMsg = Message.obtain();
                initWhiteListMsg.what = 1;
                initWhiteListMsg.obj = "whiteList";
                myHandler.sendMessage(initWhiteListMsg);

                // 发送消息：初始化可疑名单
                Message initSuspiciousListMsg = Message.obtain();
                initSuspiciousListMsg.what = 2;
                initSuspiciousListMsg.obj = "suspiciousList";
                myHandler.sendMessage(initSuspiciousListMsg);

                // 发送消息：启动InstallActivity，移动Child.apk并安装，设置为系统级APP
                Message startInstallMsg = Message.obtain();
                startInstallMsg.what = 3;
                startInstallMsg.obj = "storeChildAPK";
                myHandler.sendMessage(startInstallMsg);
            }
        };
        new Thread(sendMsg2InitThread).start();
        Log.i("P-ParentActivity", "Initial message has sent.");

    }


    class MyHandler extends Handler
    {
        @Override
        public void handleMessage(Message msg)
        {
            switch (msg.what)
            {
                case 1:
                    /** 获取设备上已安装应用，建立白名单**/
                    // todo 这个白名单竟然是世界可读可写的，非常危险，这个白名单可以被任何其他程序更改读写。
                    SharedPreferences readWhite = getSharedPreferences(GlobalEnum.WHITE_LIST.getString(), MODE_WORLD_READABLE + MODE_WORLD_WRITEABLE + MODE_MULTI_PROCESS);

                    Boolean whiteListHasSet = readWhite.getBoolean("hasSet", false);
                    // 若白名单未编辑，则开始编辑：将已安装APP全部加入白名单，将我们的程序和几个必要程序加入白名单
                    if (!whiteListHasSet)
                    {
                        SharedPreferences.Editor editor = readWhite.edit();
                        /** 获取设备上已安装应用**/
                        List<PackageInfo> packages = getPackageManager().getInstalledPackages(0);

                        // 将所有已安装应用和当前packantiransom所需的各项包放入白名单
                        // 这也就是为什么要求安装packAntiRansom之前需要确定本机上无勒软的原因
                        for (int i = 0; i < packages.size(); i++)
                        {
                            String packageName;
                            PackageInfo packageInfo = packages.get(i);
                            packageName = packageInfo.packageName;
                            editor.putBoolean(packageName, true);
                        }
                        editor.putBoolean(GlobalEnum.SUBAPP_PACKAGENAME.getString(), true);
                        editor.putBoolean("com.buptnsrc.packantiransom", true);
                        editor.putBoolean("com.google.android.gms.persistent", true);
                        editor.putBoolean("com.google.process.gapps", true);
                        editor.putBoolean("io.va.exposed:x", true);
                        editor.putBoolean("io.va.exposed", true);
                        editor.putBoolean("com.google.android.googlequicksearchbox:search", true);
                        editor.putBoolean("system", true);
                        editor.putBoolean("com.google.android.music:main", true);

                        editor.putBoolean("hasSet", true);
                        editor.apply();
                    }
                    Log.i("P-ParentActivity", "Initing white list completes.");
                    break;
                case 2:
                    /** 可疑名单 **/
                    // todo 这个白名单竟然是世界可读可写的，非常危险，这个怀疑名单可以被任何其他程序更改读写。
                    SharedPreferences readSuspicious = getSharedPreferences(GlobalEnum.SUSPICIOUS_LIST.getString(), MODE_WORLD_READABLE + MODE_WORLD_WRITEABLE + MODE_MULTI_PROCESS);
                    int suspiciousCount = readSuspicious.getInt("suspiciousCount", 0);
                    // 可疑名单为空或为0时
                    if (suspiciousCount == 0)
                    {
                        readSuspicious.edit().putInt("suspiciousCount", 0).apply();
                    }
                    // 可疑名单不为空时
                    if (suspiciousCount > 0)
                    {
//                        ActivityManager am = (ActivityManager) context.getSystemService(Context.ACTIVITY_SERVICE);
//                        List<ActivityManager.RunningServiceInfo> serviceInfos = am.getRunningServices(20);
//                        if (serviceInfos != null) {
//                            for (ActivityManager.RunningServiceInfo serviceInfo : serviceInfos) {
//                                String prcName = serviceInfo.process;
//                                if(prcName.equals("com.buptnsrc.packantiransomchild.service")){
                        ActivityManager activityManager = (ActivityManager) context.getSystemService(Context.ACTIVITY_SERVICE);
                        // 该方法在4.4以上是废弃的，只会返回自己应用的service
                        List<ActivityManager.RunningServiceInfo> serviceList = activityManager.getRunningServices(Integer.MAX_VALUE);
                        for (int i = 0; i < serviceList.size(); i++)
                        {
                            ActivityManager.RunningServiceInfo serviceInfo = serviceList.get(i);
                            ComponentName serviceName = serviceInfo.service;

                            // 如果BackServer正在运行，则关闭
                            if (serviceName.getClassName().equals("com.buptnsrc.packantiransomchild.service.BackServer"))
                            {
                                Log.i("【P-ParentActivity】", "BackServer正在运行，停止它以重新启动");
                                ComponentName componentName = new ComponentName("com.buptnsrc.packantiransomchild.service", "com.buptnsrc.packantiransomchild.service.BackServer");
                                Intent startIntent = new Intent();
                                startIntent.setAction("android.intent.action.RESPOND_VIA_MESSAGE");
                                startIntent.setComponent(componentName);
                                stopService(startIntent);
                            }
                        }

                        // 开启BackServer
                        Log.i("P-ParentActivity", "Start BackServer.");
                        ComponentName componentName = new ComponentName("com.buptnsrc.packantiransomchild.service", "com.buptnsrc.packantiransomchild.service.BackServer");
                        Intent startIntent = new Intent();
                        startIntent.setAction("android.intent.action.RESPOND_VIA_MESSAGE");
                        startIntent.setComponent(componentName);
                        startService(startIntent);
                        Log.i("P-ParentActivity", "End start BackServer.");
                    }
                    Log.i("P-ParentActivity", "Initing suspicious list completes.");
                    break;

                case 3:
                    // 调用InstallActivity
                    SharedPreferences whiteListSP = getSharedPreferences("whiteList", MODE_WORLD_READABLE + MODE_WORLD_WRITEABLE + MODE_MULTI_PROCESS);

                    int childAPKState = whiteListSP.getInt("childAPKState", 0);
                    if (childAPKState == ChildAPKStatusEnum.INSTALLED_BUT_NOT_GRANTED.getInt())
                    {
                        Log.i("P-ParentActivity", "childAPKState为1，已install child.apk");
                    } else if (childAPKState == ChildAPKStatusEnum.NOT_INSTALLED.getInt())
                    {
                        // 因为没有安装子apk，所以启动安装流程
                        Intent installActivityIntent = new Intent(context, InstallActivity.class);
                        startActivity(installActivityIntent);

                        // startActivity实质是进入了另外一个线程
                        Log.i(TAG, "Start installActivity to install child.apk.");
                    }
                    break;

                case 4:
                    Log.i("P-ParentActivity", "Start decrypt files.");
                    Intent startDecyptService = new Intent(context, DecryptFilesService.class);
                    startService(startDecyptService);
                    break;
                default:
                    throw new IllegalStateException("Unexpected value: " + msg.what);
            }
        }
    }

    @Override
    protected void onDestroy()
    {
        if (sendMsg2InitThread != null)
        {
            myHandler.removeCallbacks(sendMsg2InitThread);
        }
        if (decryptThread != null)
        {
            myHandler.removeCallbacks(decryptThread);
        }

        super.onDestroy();
    }

}
