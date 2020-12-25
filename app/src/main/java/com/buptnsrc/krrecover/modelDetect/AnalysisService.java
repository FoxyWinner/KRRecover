package com.buptnsrc.krrecover.modelDetect;

import android.app.ActivityManager;
import android.app.AlarmManager;
import android.app.IntentService;
import android.app.PendingIntent;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageManager;
import android.os.Parcelable;
import android.support.v4.app.NotificationCompat;
import android.util.Log;


import com.buptnsrc.krrecover.activity.ParentActivity;
import com.buptnsrc.krrecover.enums.GlobalEnum;

import java.util.List;

/***
 *
 *  2019.4.10
 *  调用各种类，来完成主要的流程：
 *  1、获取手机设备上已安装的所有软件信息
 *  2、对1中的所有软件提取其dex文件中所使用的API package信息
 *  3、读取模型文件
 *  4、将每个软件的API package信息放到模型中，检测该软件成为勒软的概率
 *  5、保存每个软件的概率信息
 *
 * **/

public class AnalysisService extends IntentService
{
    double isBlack = 0.8;
    double isWhite = 0.01;

    private static volatile boolean a = true;
    private int b;
    private NotificationCompat c;
    AlarmManager manager;
    public int time;
    public Context context = this;
    PendingIntent pi;

    public AnalysisService()
    {
        super("AnalysisService");
    }

    @Override
    protected void onHandleIntent(Intent intent)
    {
        Log.i("AnalysisService", "onHandleIntent");

        PackageManager packageManager = getPackageManager();
        Parcelable appInfoParcelable = null;
        String pkgName = null;

        try
        {
            ApplicationInfo applicationInfo1 = intent.getParcelableExtra("APPINFO");
            pkgName = applicationInfo1.packageName;
            appInfoParcelable = (Parcelable) packageManager.getApplicationInfo(pkgName, 0);// 03.21 在这里先测试一个软件


            ApplicationInfo applicationInfo = packageManager.getApplicationInfo(pkgName, PackageManager.GET_META_DATA);
            //CharSequence这两者效果是一样的.
            final String appName = packageManager.getApplicationLabel(applicationInfo).toString();


            String sourceDir = ((ApplicationInfo) appInfoParcelable).sourceDir;
            /**** 步骤一的话，直接到这里就可以了
             Set 应用分析结果 = AnalysisUtil.对参数2的应用进行API分析并返回分析结果(this.getApplicationContext(), 待分析应用的sourceDir);
             ***/
//        /** 这里先用virtualData替换上面的"应用分析结果"**/
//        String virtualData=com.buptnsrc.packantiransom.modelDetect.Util.AnalysisUtil.readCSV(getBaseContext());
//        Log.i("virtualData",virtualData);


            /** 对某一软件分析dex文件，并用模型判断其作为勒软的可能性**/
//            int analysisResult = com.buptnsrc.packantiransom.modelDetect.Util.AnalysisUtil.对参数2的应用进行API分析并返回分析结果(this.getApplicationContext(), sourceDir,pkgName,appName);
            int analysisResult = 1; // 0意思没有风险 ，1意味着风险很大，新需求要求所有新装应用都加入可疑检测名单

            // 无风险，放入白名单
            if (analysisResult <= isWhite)
            {
                SharedPreferences whiteList = getSharedPreferences("whiteList", MODE_WORLD_READABLE + MODE_WORLD_WRITEABLE + MODE_MULTI_PROCESS);
                whiteList.edit().putBoolean(pkgName, true).commit();
            } else // 放入可疑名单，在新需求中，要求所有新装应用加入该列表
            {
                SharedPreferences suspiciousList = getSharedPreferences("suspiciousList", MODE_WORLD_READABLE + MODE_WORLD_WRITEABLE + MODE_MULTI_PROCESS);

                Boolean isSuspicious = suspiciousList.getBoolean(pkgName, false);
                if (!isSuspicious)
                {
                    suspiciousList.edit().putBoolean(pkgName, true).commit();
                    int count = suspiciousList.getInt("suspiciousCount", 0);
                    count++;
                    suspiciousList.edit().putInt("suspiciousCount", count).commit();
                    Log.i("【P-AnalysisService】", "新增可疑app：" + pkgName);
                }


                Log.i("【P-AnalysisService】", "可疑app数：" + suspiciousList.getInt("suspiciousCount", 0));
                ActivityManager activityManager = (ActivityManager) context.getSystemService(Context.ACTIVITY_SERVICE);
                List<ActivityManager.RunningServiceInfo> serviceList = activityManager.getRunningServices(Integer.MAX_VALUE);
                Log.i("【P-AnalysisService】", "当前运行service：" + serviceList);


                // 从service列表中看我们的BackServer是否运行，如果已运行，则停止他
                for (int i = 0; i < serviceList.size(); i++)
                {
                    ActivityManager.RunningServiceInfo serviceInfo = serviceList.get(i);
                    ComponentName serviceName = serviceInfo.service;
                    if (serviceName.getClassName().equals(GlobalEnum.SUBAPP_PACKAGENAME.getString() + ".service.BackServer"))
                    {
                        Log.i("【P-AnalysisService】", "BackServer正在运行，停止它以重新启动");
                        ComponentName componentName = new ComponentName(GlobalEnum.SUBAPP_PACKAGENAME.getString(), GlobalEnum.SUBAPP_PACKAGENAME.getString() + ".service.BackServer");
                        Intent startIntent = new Intent();
                        startIntent.setComponent(componentName);
                        startIntent.setAction("android.intent.action.RESPOND_VIA_MESSAGE");
                        stopService(startIntent);
                    }
                }
                Log.i("【P-AnalysisService】", "Start BackServer.");

                Intent startIntent = new Intent();
                ComponentName componentName = new ComponentName(GlobalEnum.SUBAPP_PACKAGENAME.getString(), GlobalEnum.SUBAPP_PACKAGENAME.getString() + ".service.BackServer");
                startIntent.setComponent(componentName);
                startIntent.setAction("android.intent.action.RESPOND_VIA_MESSAGE");
                startService(startIntent);

                Log.i("【P-AnalysisService】", "End start BackServer.");

                // 接下来校验我们的service是否启动成功，验证结果是确实没有被启动成功
                Thread.sleep(1000L);
                serviceList = activityManager.getRunningServices(Integer.MAX_VALUE);
                Log.i("【P-AnalysisService】", "当前运行service：\n");
                for (int i = 0; i < serviceList.size(); i++)
                {
                    ActivityManager.RunningServiceInfo serviceInfo = serviceList.get(i);
                    ComponentName serviceName = serviceInfo.service;
                    Log.i("【P-AnalysisService】", serviceName + "\n");

                    if (serviceName.getClassName().equals(GlobalEnum.SUBAPP_PACKAGENAME.getString() + ".service.BackServer"))
                    {
                        Log.i("【P-AnalysisService】", "出现了！");
                    }
                }
                Log.i("【P-AnalysisService】", "验证结束");

            }


            if (ParentActivity.context == null)
            {
                Log.i("【P-AnalysisService】", "MainActivity restart");
                Intent startActivityintent = new Intent();  //启动服务
                startActivityintent.setClass(context, ParentActivity.class);
                startActivityintent.setFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
                startActivityintent.putExtra("appName", appName);
                startActivity(startActivityintent);
            }
//                MainActivity.window(appName);
        }
//        catch (IOException e) {
//            e.printStackTrace();
//        }
        catch (PackageManager.NameNotFoundException | InterruptedException e)
        {
            e.printStackTrace();
        }
    }


}









