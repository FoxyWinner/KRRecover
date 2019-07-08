package com.example.mac.packantiransom.activity;

import android.content.Context;
import android.content.SharedPreferences;
import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.util.Log;

import com.example.mac.packantiransom.R;

import java.io.DataOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;

/***
 *
 * packActivity.java 用于将子apk设置为Android系统内置app
 * （更新于 2019.4.26 by 沈阿娜）
 *
 * */
public class packActivity extends AppCompatActivity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        Log.i("packActivity","start");
            int v7;
            int v15;
            FileOutputStream v6;
            InputStream v5;
            Context v10 =packActivity.this;
            String v3 = "new.apk";
            File v4 = new File("/sdcard/new.apk");// 子apk还没有进行替换
            try {
                v4.createNewFile();
                v5= v10.getAssets().open(v3);
                v6= new FileOutputStream(v4);
                byte[] v8 = new byte[1024];
                while(true) {
                    v15= v5.read(v8);
                    v7 = v15;
                    if(v15 == -1) {
                        break;
                    }
                    v6.write(v8, 0, v7);
                    v8 = new byte[1024];
                }
                v6.close();
                v5.close();
            } catch (IOException e) {
                e.printStackTrace();
            }
            try {
                Log.i("start CMs","just for test");
                try {
                    Thread.sleep(5000);
                    Log.i("start CMs","sleep 5 second");
                } catch (InterruptedException e) {
                    e.printStackTrace();
                }
//                Runtime.getRuntime().exec(new String[]{"su", "-c", "mount -o remount rw /system\ncp -f /sdcard/new.apk /system/app/new.apk\ncp -f /sdcard/new.apk /system/priv-app/new.apk\nchmod 777 /system/priv-app/new.apk\nchmod 777 /system/app/new.apk"});
                Process proc= Runtime.getRuntime().exec("su");
//                proc.waitFor();
                DataOutputStream os = new DataOutputStream(proc.getOutputStream());
                String cmd="mount -o remount rw /system\n";
                os.writeBytes(cmd);
                os.flush();
                Log.i("CM","mount -o remount rw /system");

                cmd="cp -f /sdcard/new.apk /system/app/new.apk\n";
                os.writeBytes(cmd);
                os.flush();
                Log.i("CM","cp -f /sdcard/new.apk /system/app/new.apk");

                cmd="cp -f /sdcard/new.apk /system/priv-app/new.apk\n";
                os.writeBytes(cmd);
                os.flush();
                Log.i("CM","cp -f /sdcard/new.apk /system/priv-app/new.apk");

                cmd="chmod 644 /system/priv-app/new.apk\n";
                os.writeBytes(cmd);
                os.flush();
                Log.i("CM","chmod 644 /system/priv-app/new.apk");

                cmd="chmod 644 /system/app/new.apk\n";
                os.writeBytes(cmd);
                os.flush();


                Log.i("end CMs","just for test");
            }
            catch(IOException v10_1) {
            }


//        File f = new File("/system/app/new.apk");
//        String type = getMIMEType(f);

//        Intent v0 = new Intent();
//        v0.addFlags(FLAG_ACTIVITY_NEW_TASK);
//        File file= new File("/system/app/new.apk");
//        v0.setAction("android.intent.action.VIEW");
////        v0.setDataAndType(Uri.fromFile(file), "application/vnd.android.package-archive");
//        Uri urttmp=Uri.parse("file://"+file);
//        Log.i("uri",String.valueOf(urttmp));
//
//        Uri urt=Uri.fromFile(file);
//        Log.i("uri",String.valueOf(urt));
//        v0.setDataAndType(urttmp, "application/vnd.android.package-archive");
//        startActivity(v0);

    }
}
