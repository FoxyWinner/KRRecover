package com.buptnsrc.krrecover.activity;

import android.content.Context;
import android.content.SharedPreferences;
import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.util.Log;

import com.buptnsrc.krrecover.enums.ChildAPKStatusEnum;

import java.io.DataOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;

/***
 *
 * packActivity.java 用于将子apk设置为Android系统内置app
 * TODO 该类并没有做任何需要用户界面交互的操作，需要重构为Service
 *
 * */
public class InstallActivity extends AppCompatActivity
{
    private static final String TAG = "P-InstallActivity";

    @Override
    protected void onCreate(Bundle savedInstanceState)
    {
        super.onCreate(savedInstanceState);
        Log.i("【P-InstallActivity】", "Activity creates.");

        int readBytesNum;
        FileOutputStream fileOutputStream;
        InputStream inputStream;
        Context context = InstallActivity.this;

        // 1. 将资源文件下的krrecoversub.apk拷贝至sdcard下
        String subApkName = "krrecoversub.apk";
        File subAPKFile = new File("/sdcard/" + subApkName);
        try
        {
            subAPKFile.createNewFile();
            inputStream = context.getAssets().open(subApkName);
            fileOutputStream = new FileOutputStream(subAPKFile);
            byte[] bytes = new byte[1024];

            while (true)
            {
                readBytesNum = inputStream.read(bytes);

                if (readBytesNum == -1)
                {
                    Log.i(TAG, "readBytes失败，意味着read到尾部了");
                    break;
                }
//                Log.i("P-InstallActivity", "readBytes成功"+readBytesNum);
                fileOutputStream.write(bytes, 0, readBytesNum);
                bytes = new byte[1024];
            }
            fileOutputStream.close();
            inputStream.close();
        } catch (IOException e)
        {
            e.printStackTrace();
        }

        // 2. 为父APK请求Root权限并安装子APK，授予644权限


        Log.i(TAG, "Start CMDs.");

        // 安装子APK并授权
        int result = -1;// 可用作分支控制
        String CMD = "mount -o remount rw /system\ncp -f /sdcard/" + subApkName + " /system/app/" + subApkName + "\ncp -f /sdcard/" + subApkName + " /system/priv-app/" + subApkName + "\nchmod 644 /system/priv-app/" + subApkName + "\nchmod 644 /system/app/" + subApkName + "\n";
        result = execRootCmdSilent(CMD);
        Log.i(TAG, result == 0 ? "成功" : "失败");
        Log.i(TAG, "End CMDs.");

        if (result == 0)
        {
            SharedPreferences whiteListSP = getSharedPreferences("whiteList", MODE_WORLD_READABLE + MODE_WORLD_WRITEABLE + MODE_MULTI_PROCESS);
            SharedPreferences.Editor editor = whiteListSP.edit();
            editor.putInt("childAPKState", ChildAPKStatusEnum.INSTALLED_BUT_NOT_GRANTED.getInt());
            editor.apply();
        }

        //删除sdcard下的apk包
        subAPKFile.delete();


        // 最后再reboot一下确认系统级应用生效
        Log.i(TAG, "Start reboot.");
        String rebootCMD = "reboot";
        result = execRootCmdSilent(rebootCMD);



        finish();
        // 重启之后子apk会receive到reboot事件而自动启动且索取授权

    }


    public int execRootCmdSilent(String cmd)
    {
        int result = -1;
        DataOutputStream dos = null;
        try
        {
            Process p = Runtime.getRuntime().exec("su");
            dos = new DataOutputStream(p.getOutputStream());
            dos.writeBytes(cmd + "\n");
            dos.flush();
            dos.writeBytes("exit\n");
            dos.flush();
            p.waitFor();
            result = p.exitValue();
            Log.i(TAG, "Success execRootCmdSilent(" + cmd + ")=" + result);
        } catch (Exception e)
        {
            e.printStackTrace();
            Log.e(TAG,
                    "execRootCmdSilent(" + cmd + "),Exception:"
                            + e.getMessage());
        } finally
        {
            if (dos != null)
            {
                try
                {
                    dos.close();
                } catch (IOException e)
                {
                    e.printStackTrace();
                }
            }
        }
        return result;
    }

    @Override
    protected void onDestroy()
    {

        super.onDestroy();
    }
}
