package com.example.mac.packantiransom.modelDetect;

import android.app.ActivityManager;
import android.app.AlarmManager;
import android.app.AlertDialog;
import android.app.IntentService;
import android.app.PendingIntent;
import android.content.ComponentName;
import android.content.Context;
import android.content.DialogInterface;
import android.content.Intent;
import android.content.SharedPreferences;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageManager;
import android.os.Handler;
import android.os.Parcelable;
import android.support.v4.app.NotificationCompat;
import android.util.Log;
import android.view.WindowManager;


import com.example.mac.packantiransom.MainActivity;

import java.io.IOException;
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

public class AnalysisService extends IntentService {
    double isBlack=0.8;
    double isWhite=0.01;

    private static volatile boolean a = true;
    private int b;
    private NotificationCompat c;
    AlarmManager manager;
    public int time ;
    public Context context=this;
    PendingIntent pi;

    static {
    }

    public AnalysisService() {
        super("AnalysisService");

    }

    protected void onHandleIntent(Intent arg39) {
        Log.i("AnalysisService","onHandleIntent");

        /***
        try {
            raw下B文件内容 = AnalysisUtil.a_获取raw目录下某文件内容并保存成HashMap格式(this.getApplicationContext());
        } catch (IOException e) {
            e.printStackTrace();
        }
         ***/
//      raw下B文件内容 = ((HashMap) v2_1);
//        raw下B文件内容=new HashMap();
//        Parcelable 待测软件的应用信息 = 调用该intentService的Intent变量.getParcelableExtra("APPINFO");

        PackageManager v2 = getPackageManager();
        Parcelable 待测软件的应用信息 = null;
        String pkgName=null;

        try {
            ApplicationInfo v2_1=arg39.getParcelableExtra("APPINFO");
            pkgName=v2_1.packageName;
            待测软件的应用信息 = (Parcelable)v2.getApplicationInfo(pkgName, 0);// 03.21 在这里先测试一个软件


            PackageManager packageManager = getPackageManager();
            ApplicationInfo applicationInfo = packageManager.getApplicationInfo(pkgName, PackageManager.GET_META_DATA);
            //CharSequence这两者效果是一样的.
            final String appName = String.valueOf(packageManager.getApplicationLabel(applicationInfo).toString());


        String 待分析应用的sourceDir = ((ApplicationInfo) 待测软件的应用信息).sourceDir;
        /**** 步骤一的话，直接到这里就可以了
        Set 应用分析结果 = AnalysisUtil.对参数2的应用进行API分析并返回分析结果(this.getApplicationContext(), 待分析应用的sourceDir);
***/
//        /** 这里先用virtualData替换上面的"应用分析结果"**/
//        String virtualData=com.example.mac.packantiransom.modelDetect.Util.AnalysisUtil.readCSV(getBaseContext());
//        Log.i("virtualData",virtualData);


            /** 对某一软件分析dex文件，并用模型判断其作为勒软的可能性**/
            int 应用分析结果 = com.example.mac.packantiransom.modelDetect.Util.AnalysisUtil.对参数2的应用进行API分析并返回分析结果(this.getApplicationContext(), 待分析应用的sourceDir,pkgName,appName);
            if (应用分析结果 <= isWhite){
                SharedPreferences readWhite = getSharedPreferences("whiteList", MODE_WORLD_READABLE+MODE_WORLD_WRITEABLE+MODE_MULTI_PROCESS);
                readWhite.edit().putBoolean(pkgName,true).commit();
            }
            else {
                SharedPreferences readSuspicious = getSharedPreferences("suspiciousList", MODE_WORLD_READABLE+MODE_WORLD_WRITEABLE+MODE_MULTI_PROCESS);
                if(!readSuspicious.getBoolean(pkgName,false)){
                    readSuspicious.edit().putBoolean(pkgName,true).commit();
                    int count=readSuspicious.getInt("suspiciousCount",0);
                    count=count+1;
                    readSuspicious.edit().putInt("suspiciousCount",count).commit();

                }
                Log.i("suspiciousList_DATA",String.valueOf(readSuspicious.getInt("suspiciousCount",0)));
                ActivityManager activityManager = (ActivityManager) context.getSystemService(Context.ACTIVITY_SERVICE);
                List<ActivityManager.RunningServiceInfo> serviceList = activityManager.getRunningServices(Integer.MAX_VALUE);
                for (int i = 0; i < serviceList.size(); i++) {
                    ActivityManager.RunningServiceInfo serviceInfo = serviceList.get(i);
                    ComponentName serviceName = serviceInfo.service;
                    if (serviceName.getClassName().equals("com.example.mac.test1.BackServer")) {
//                        Intent startIntent = new Intent("com.example.mac.startBackServer");
//                        startIntent.setPackage("com.example.mac.test1");
                        ComponentName componentName=new ComponentName("com.example.mac.test1","com.example.mac.test1.BackServer");
                        Intent startIntent=new Intent();
                        startIntent.setComponent(componentName);
                        startIntent.setAction("android.intent.action.RESPOND_VIA_MESSAGE");
                        stopService(startIntent);
                    }
                }
                Log.i("AnalysisService", "start BackServer");
//                Intent startIntent = new Intent("com.example.mac.startBackServer");
//                startIntent.setPackage("com.example.mac.test1");
//                startService(startIntent);
                ComponentName componentName=new ComponentName("com.example.mac.test1","com.example.mac.test1.BackServer");
                Intent startIntent=new Intent();
                startIntent.setComponent(componentName);
                startIntent.setAction("android.intent.action.RESPOND_VIA_MESSAGE");
                startService(startIntent);
                Log.i("AnalysisService", "end BackServer");
            }



                if(MainActivity.context==null){
                    Log.i("AnalysisService","MainActivity restart");
                    Intent startActivityintent=new Intent();  //启动服务
                    startActivityintent.setClass(context,MainActivity.class);
                    startActivityintent.setFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
                    startActivityintent.putExtra("appName",appName);
                    startActivity(startActivityintent);
                }
//                MainActivity.window(appName);



        } catch (IOException e) {
            e.printStackTrace();
        } catch (PackageManager.NameNotFoundException e) {
            e.printStackTrace();
        }


        /***
         *
         try {
         //            raw下A文件内容_APIList = d.a_将raw目录下的某文件放到该应用目录下的指定文件夹内_并返回该文件内容(该AnalysisService实例.getString(v0), this.getApplicationContext());
         String s="apipackagelist.txt";
         raw下A文件内容_APIList = FeaturesUtil.a_读取apipackagelist到应用目录下(s, this.getApplicationContext());

         } catch (ClassNotFoundException v0_1) {
         //            raw下B文件内容 = ((HashMap) v2_1);
         raw下A文件内容_APIList =new String[]{};

         raw下B文件内容=new HashMap();
    } catch (IOException e) {
        raw下A文件内容_APIList =new String[]{};

         raw下B文件内容=new HashMap();
    }
        String[] v02_raw下A文件内容_APIList = raw下A文件内容_APIList;
        HashMultiset 应用分析结果 = AnalysisUtil.对参数2的应用进行API分析并返回分析结果(this.getApplicationContext(), 待分析应用的sourceDir, v02_raw下A文件内容_APIList);
        ***/

/*** 暂时只获取HashMulitiset***/
        /*** 先看应用分析提取成功了，下面的以后再看

        int v4 = 2131623936;
        long v17 = 1024;
        int v2_2 = 2131755188;
        // R-PackDroid 在这有个switch case，在这里我只选取了其中一种情况，即"myapp_scan"

        HashMap v11_raw下B文件内容_疑似是knownlist_即黑白名单 = raw下B文件内容;
        MyPreferenceManager v10_2 = new MyPreferenceManager(this.getApplicationContext());
        v10_2.b_设置IsCurrentMyAppCompleted的值(false);

        CharSequence 待测软件的名字 = v8_PackageManager.getApplicationLabel(((ApplicationInfo) 待测软件的应用信息));

        String 待分析应用的packageName = ((ApplicationInfo) 待测软件的应用信息).packageName;
        该AnalysisService实例.b = 1;
//        this.a_对icon与sound等值赋值并封装一个有关MainActivity的intent(该AnalysisService实例.getString(v2_2), 待测软件的名字, true, false, v16当前值暂时为2, false);  // v2_2此时为2131755188
        File 待分析应用的路径文件 = new File(Uri.parse(待分析应用的sourceDir).getPath());
        long 待分析应用的路径文件的大小 = 待分析应用的路径文件.length() / v17;  // v17为1024
//        if (该AnalysisService实例.e_boolean变量) {
//            Crashlytics.log(4, "AnalysisService", "NewApp Mode: analysis starting");  // 要开始分析应用啦，激动激动
//        }


         Bundle 应用分析结果 = AnalysisUtil.对参数2的应用进行API分析并返回分析结果(this.getApplicationContext(), 待分析应用的sourceDir, v02_raw下A文件内容_APIList);
        待测应用的md5 = it.mscalas.rpackdroid.c.b.获取md5(待分析应用的路径文件);

        if (v11_raw下B文件内容_疑似是knownlist_即黑白名单.containsKey(待测应用的md5)) {
            v1_1 = v11_raw下B文件内容_疑似是knownlist_即黑白名单.get(待测应用的md5).intValue();
            v11_1 = v1_1;
        } else if (应用分析结果 == null) {
            v11_1 = 3;
        } else {
            v1_1 = 应用分析结果.getInt("AA_RESULT");
            v11_1 = v1_1;
        }

        if (应用分析结果 == null) {
//            if(该AnalysisService实例.e_boolean变量) {
//                Crashlytics.log(6, "AnalysisService", "NewApp Mode: analysis exception occurred");
//            }
            v0_4 = " ";
            待测应用的md5 = " ";
            if (v11_1 == 3) {
                com.example.mac.antiransom.MyApplication.a_保存变量c的值(com.example.mac.antiransom.MyApplication.c() + 1);
                待分析应用的sourceDir = v0_4;
                v7_2 = 待测应用的md5;
                v0 = 1;
            } else {
                待分析应用的sourceDir = v0_4;
                v7_2 = 待测应用的md5;
                v0 = 0;
            }
        } else {
            Log.i("AnalysisService", "NewApp analysis done");
            待测应用的md5 = new e().a(应用分析结果.getStringArrayList("MOSTCALLED"));
            v7_2 = 应用分析结果.getString("AA_PROBABILITIES");
            待分析应用的sourceDir = 待测应用的md5;
            v0 = 0;
        }

        Cursor v15_2 = this.getContentResolver().query(b.a, new String[]{"_id"}, "package_name=?", new String[]{待分析应用的packageName}, null);
        if (v15_2 != null) {
            if (v15_2.getCount() == 0) {
                this.a_将参数信息添加到数据库中(待测软件的名字, 待分析应用的packageName, 待分析应用的路径文件的大小, v11_1, v7_2, 待分析应用的sourceDir);
            } else {
                v15_2.moveToFirst();
                this.a_保存app检测结果(v15_2.getInt(v15_2.getColumnIndex("_id")), 待测软件的名字, 待分析应用的路径文件的大小, v11_1, v7_2, 待分析应用的sourceDir);
            }

            v15_2.close();
        }

        v10_2.e();
        v10_2.b_设置IsCurrentMyAppCompleted的值(true);
        com.example.mac.antiransom.MyApplication.a_设置boolean变量a的值(false);
        该AnalysisService实例.d.cancel(23);
        if (v0 > 0) {
            this.a_对icon与sound等值赋值并封装一个有关MainActivity的intent(该AnalysisService实例.getString(2131755187), this.getResources().getQuantityString(2131623937, com.example.mac.antiransom.MyApplication.c(), new Object[]{Integer.valueOf(com.example.mac.antiransom.MyApplication.c())}), true, true, v16当前值暂时为2, true);
            return;
        }

        v0 = 2131755190;
        if (v11_1 == 0) {
//            this.a_对icon与sound等值赋值并封装一个有关MainActivity的intent(该AnalysisService实例.getString(2131755187), 该AnalysisService实例.getString(v0, new Object[]{待测软件的名字, v14[v11_1]}), true, false, 2, true);
            // 先把v14等跟资源有关的去了
            this.a_对icon与sound等值赋值并封装一个有关MainActivity的intent(该AnalysisService实例.getString(2131755187), 该AnalysisService实例.getString(v0, new Object[]{待测软件的名字}), true, false, 2, true);
            return;
        }

        this.a_对icon与sound等值赋值并封装一个有关MainActivity的intent(该AnalysisService实例.getString(2131755187), 该AnalysisService实例.getString(v0, new Object[]{待测软件的名字, v14[v11_1]}), true, true, 2, true);

         return;
         *
         */
    }

//    private void a(int arg3,String arg4,long arg5,int arg7,String arg8,String arg9){
//        ContentValues v0=new ContentValues();
//        v0.put("name",arg4);
//        v0.put("size",Long.valueOf(arg5));
//        v0.put("result",Integer.valueOf(arg7));
//        v0.put("api",arg9);
//        v0.put("probabilities",arg8);
//        v0.put("time",Long.valueOf(System.currentTimeMillis()));
//        arg3=this.getContentResolver().update(b.a,v0,"_id=?",new String[]{Integer.toString(arg3)})
////        if(this.e){
////        }
//    }
//
//    private void a(String arg2){
//        this.a(arg2,0);
//        Object v2=this.getApplicationContext().getSystemService(NOTIFICATION_SERVICE);
//        if(v2!=null){
//            ((NotificationManager)v2).cancelAll();
//        }
//    }
//
//    private void a(String arg5,int arg6){
//        Intent v0=new Intent(arg5);
//        v0.putExtra("TOTAL",this.b);
//        v0.putExtra("LEFT",arg6);
//        LocalBroadcastManager.a(((Context)this)).a(v0);
//    }
//
//
//    private void a(String arg3,String arg4,long arg5,int arg7,String arg8,String arg9){
//        ContentValues v0=new ContentValues();
//        v0.put("name",arg3);
//        v0.put("package_name",arg4);
//        v0.put("size",Long.valueOf(arg5));
//        v0.put("result",Integer.valueOf(arg7));
//        v0.put("probabilities",arg8);
//        v0.put("api",arg9);
//        v0.put("time",Long.valueOf(System.currentTimeMillis()));
//        Uri v3=this.getContentResolver().insert(b.a,v0);
////        if(this.e){
////
////        }
//    }
//
//
//
//    private  static boolean a(){
//        return AnalysisService.a;
//    }


//    public static void A(boolean arg1) {
//        try {
//            AnalysisService.a = arg1;
//        }
//        catch(Throwable v1) {
//            throw v1;
//        }
//    }

//    public void onTaskRemoved(Intent arg3){
//        Object v0=this.getApplicationContext().getSystemService(NOTIFICATION_SERVICE);
//        if(v0!=null){
//            ((NotificationManager)v0).cancelAll();
//        }
//        super.onTaskRemoved(arg3);
//    }


}









