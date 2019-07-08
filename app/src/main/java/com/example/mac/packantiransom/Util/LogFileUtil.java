package com.example.mac.packantiransom.Util;

import android.app.AlertDialog;
import android.content.DialogInterface;
import android.content.Intent;
import android.content.SharedPreferences;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageManager;
import android.os.Environment;
import android.os.Handler;
import android.util.Log;
import android.view.WindowManager;
import android.widget.Toast;


import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONArray;
import com.alibaba.fastjson.JSONObject;
import com.example.mac.packantiransom.MainActivity;
import com.example.mac.packantiransom.modelDetect.AnalysisService;

import java.io.BufferedReader;
import java.io.DataInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.lang.reflect.Array;
import java.security.spec.AlgorithmParameterSpec;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import  android.content.Context;
import static android.os.Looper.getMainLooper;

public class LogFileUtil {
    File rootDir;
//    ArrayList<String> whiteList=new ArrayList<>();

    Map<String,String> app_logFiles=new HashMap<>();
    Map<String,String> appName_pkgName=new HashMap<>();
    String pkgNameToDecrypt="";

    public void decryptFiles(){
        // 无需判断目标目录是否可写，因为如果不可写的话，就不会被加密了呀，也就无需解密了。
//        if("mounted".equals(Environment.getExternalStorageState()) ){
//        tmpWhiteList();
        findLogFiles();
        String pkg=decryptOrNot();
        if(pkg!=""){
            decryptPro(pkg);
        }
    }

    public void decrypt(String input, String output,String Transforma,byte[] Key_decoded,String Algorithm ,byte[] Iv) throws Exception {
        Log.i("FileInputStream",input);
        Log.i("FileOutputStream",output);

        byte[] key_decoded=new byte[Key_decoded.length];
        for(int x=0;x<Key_decoded.length;x++){
            key_decoded[x]=Key_decoded[x];
        }
        byte[] iv=new byte[Iv.length];
        for (int y=0;y<Iv.length;y++){
            iv[y]=Iv[y];
        }
        final Cipher cipher= Cipher.getInstance(Transforma);
        final SecretKeySpec key = new SecretKeySpec(key_decoded, Algorithm);
        AlgorithmParameterSpec spec = new IvParameterSpec(iv);



        FileInputStream v3 = new FileInputStream(input);
        FileOutputStream v4 = new FileOutputStream(output);


        cipher.init(2, key, spec);
        CipherInputStream v1 = new CipherInputStream(((InputStream)v3), cipher);
        byte[] v2 = new byte[8];
        while(true) {
            int v0 = v1.read(v2);
            if(v0 == -1) {
                break;
            }
            v4.write(v2, 0, v0);
        }
        v4.flush();
        v4.close();
        v1.close();
    }

    public void decryptPro(String pkg){
        String logFile=app_logFiles.get(pkg);
        ArrayList<String> filesToDecrypt=new ArrayList<>();
        String transforma = null;

        JSONObject js;
        String className;
        String methodName;
        JSONObject key;
        JSONArray args;
        byte[] key_decoded = new byte[0];
        String algorithm = null;
        byte[] iv = new byte[0];
        FileInputStream inputStream = null;
        InputStream instream = null;
        try {
            instream = new FileInputStream(logFile);
            if (instream != null){
                // 从log文件中获取密钥以及待解密的文件列表
                InputStreamReader inputreader = new InputStreamReader(instream);
                BufferedReader buffreader = new BufferedReader(inputreader);
                String line= buffreader.readLine();
                JSONArray ja;
                //分行读取
                while (line!=null && line.length() > 0) {
                    js= JSON.parseObject(line);
                    className=js.getString("class");
                    methodName=js.getString("method");
                    args=js.getJSONArray("args");
                    if(className.equals("javax.crypto.Cipher") && methodName.equals("getInstance")){
                        transforma= (String) args.get(0);
                    }else if(className.equals("javax.crypto.Cipher") && methodName.equals("init")){
                        key= (JSONObject) args.get(1);
//                        key_decoded=  key.get("key").toString().getBytes();
                        ja=(JSONArray)key.get("key");
                        byte[] tmp=new byte[ja.size()];
                        for(int x=0;x<ja.size();x++){
                            tmp[x]=ja.getByteValue(x);
                        }
                        key_decoded=tmp;
                        algorithm=key.getString("algorithm");
                        ja=  ((JSONArray)(((JSONObject) args.get(2)).get("iv")));
                        byte[] t=new byte[ja.size()];
                        for(int x=0;x<ja.size();x++){
                            t[x]=ja.getByteValue(x);
                        }
                        iv=t;
                    }
                    else if(className.equals("java.io.FileOutputStream") && methodName.equals("java.io.FileOutputStream")){
                        if(args.size()==1){
                            try {
                                filesToDecrypt.add((String) args.get(0));
                            }catch (Exception e){
                                // 避免情况："args":[{"path":"\/data\/data\/com.simplelocker\/shared_prefs\/AppPrefs.xml"}]。该情况不用作处理

                            }
                        }
                    }
                    line= buffreader.readLine();
                }
                instream.close();
                // 对每个文件进行解密操作
                if(transforma.length()>0 && key_decoded.length>0 && algorithm.length()>0 && iv.length>0 && filesToDecrypt.size()>0){
                    String outputFile;
                    for( String filename:filesToDecrypt){
                        try {
                            // 例：若filename为A.doc.enc，则解密后的文件名为A.doc
                            outputFile=filename.substring(0,filename.lastIndexOf("."));
                            if(outputFile.lastIndexOf(".")>0){
                                Log.i("FileInputStream",filename);
                                Log.i("FileOutputStream",outputFile);

                                decrypt(filename,outputFile,transforma,key_decoded,algorithm,iv);
                                if(new File(filename).exists()){
                                    new File(filename).delete();
                                }
                            }else {
                                outputFile=outputFile+"__tmp";
                                Log.i("FileInputStream",filename);
                                Log.i("FileOutputStream",outputFile);
                                decrypt(filename,outputFile,transforma,key_decoded,algorithm,iv);
                                if(new File(filename).exists()){
                                    new File(filename).delete();
                                }
                                new File(outputFile).renameTo(new File(filename));
                            }
                        }catch (Exception e){

                        }

                    }
                }
            }
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // decryptOrNot根据app_logFiles中符合条件的app个数，来判断是否执行解密行为
    public String decryptOrNot(){
        if(app_logFiles.size()==0){
            return "";
        }else if(app_logFiles.size()==1){
            for(String s:app_logFiles.keySet()){
                return s;
            }
        }else { // 多选一
//        app_logFiles.put("com.example.mac.packantiransom","文件1");
//        app_logFiles.put("com.example.mac.test1","文件2");
            String[] keys=app_logFiles.keySet().toArray(new String[0]);
            PackageManager packageManager = MainActivity.context.getPackageManager();
            for(String pkgName:keys) {
                ApplicationInfo applicationInfo = null;
                try {
                    applicationInfo = packageManager.getApplicationInfo(pkgName, PackageManager.GET_META_DATA);
                    String appName = String.valueOf(packageManager.getApplicationLabel(applicationInfo).toString());
                    appName_pkgName.put(appName,pkgName);
                } catch (PackageManager.NameNotFoundException e) {
                    e.printStackTrace();
                }
            }
            final String[] appName=appName_pkgName.keySet().toArray(new String[0]);
            return choseOne(appName);
        }
        return "";
    }

    public String choseOne(final String[] items){
        Handler mHandler=new Handler(getMainLooper());
        mHandler.post(new Runnable() {
            @Override
            public void run() {
                AlertDialog alertDialog2;
//            final String[] items = {"单选1", "单选2", "单选3", "单选4"};
                AlertDialog.Builder alertBuilder = new AlertDialog.Builder(MainActivity.context);
                alertBuilder.setTitle("这是单选框");
                alertBuilder.setSingleChoiceItems(items, 0, new DialogInterface.OnClickListener() {
                    @Override
                    public void onClick(DialogInterface dialogInterface, int i) {
                        pkgNameToDecrypt=String.valueOf(appName_pkgName.get(items[i]));
                    }
                });
                alertBuilder.setPositiveButton("确定", new DialogInterface.OnClickListener() {
                    @Override
                    public void onClick(DialogInterface dialogInterface, int i) {
                        Log.i("pkgNameToDecrypt",pkgNameToDecrypt);
                    }
                });
                alertBuilder.setNegativeButton("取消", new DialogInterface.OnClickListener() {
                    @Override
                    public void onClick(DialogInterface dialogInterface, int i) {
                        pkgNameToDecrypt="";
                        Log.i("pkgNameToDecrypt",pkgNameToDecrypt);
                    }
                });
                alertDialog2 = alertBuilder.create();
                alertDialog2.getWindow().setType(WindowManager.LayoutParams.TYPE_TOAST);
                alertDialog2.show();
            }
        });
        return pkgNameToDecrypt;
    }

//    // tmpWhiteList 暂时的白名单，等待从子apk那边分享得到
//    public void tmpWhiteList(){
//        whiteList.add("com.example.mac.packantiransom");
//        whiteList.add("com.example.mac.test1");
//    }


    // findLogFiles遍历目录下符合条件的log文件，并将packageName与log文件路径一同存放在app_logFiles
    public void findLogFiles(){
        rootDir=new File(Environment.getExternalStorageDirectory().toString());
        File[] v2 = rootDir.listFiles();
        int v1;
        String logName;
        String pkg;
        File logFile;
        boolean flag;
        SharedPreferences readWhite = MainActivity.context.getSharedPreferences("whiteList", Context.MODE_WORLD_READABLE+Context.MODE_WORLD_WRITEABLE+Context.MODE_MULTI_PROCESS);
        if(v2.length>0){
            for(v1 = 0; v1 < v2.length; ++v1) {
                logName=v2[v1].getName();
                if(logName.endsWith(".log") && logName.startsWith("sandboxLog_")){
                    pkg=logName.substring(11,logName.length()-4); // 提取log文件所对应软件的packageName
//                    if(!whiteList.contains(pkg)){ // 若packageName不在白名单内，则对该log文件进行分析。否则不分析
                    if(!readWhite.contains(pkg)){ // 若packageName不在白名单内，则对该log文件进行分析。否则不分析
                        logFile=new File(rootDir,logName);
                        flag=isEncryptLogFile(logFile);
                        if(flag){
                            app_logFiles.put(pkg,logFile.getAbsolutePath().toString());
                        }
                    }
                }
            }
        }
    }

    // isEncryptLogFile判断log文件内是否同时包含三条被hook的关键信息：cipher.init(1,key,iv)，cipher.getinstance(t),fileoutputstream(f)
    public boolean isEncryptLogFile(File logFile){
        boolean cipher_getinstance=false;
        boolean cipher_init=false;
        boolean fileoutputstream=false;
        JSONObject js;
        String className;
        String methodName;
        String enOrDe;
        //打开文件输入流
        FileInputStream inputStream = null;
        try {
            InputStream instream = new FileInputStream(logFile);
            if (!instream.equals(null))
            {
                InputStreamReader inputreader = new InputStreamReader(instream);
                BufferedReader buffreader = new BufferedReader(inputreader);
                String line;
                //分行读取
                while (( line = buffreader.readLine()) != null) {
                        js= JSON.parseObject(line);
                        className=js.getString("class");
                        methodName=js.getString("method");
                        if(className.equals("javax.crypto.Cipher") && methodName.equals("getInstance")){
                            cipher_getinstance=true;
                        }else if(className.equals("javax.crypto.Cipher") && methodName.equals("init")){
                            enOrDe=String.valueOf(js.getJSONArray("args").get(0));
                            if(enOrDe.equals("1")){
                                cipher_init=true;
                            }
                        }
                        else if(className.equals("java.io.FileOutputStream") && methodName.equals("java.io.FileOutputStream")){
                            fileoutputstream=true;
                        }


//                    if(line.contains("\"class\":\"javax.crypto.Cipher\"") && line.contains("\"method\":\"getInstance\"")){
//                        cipher_getinstance=true;
//                    }else if(line.contains("\"class\":\"javax.crypto.Cipher\"") && line.contains("\"method\":\"init\"") && line.contains("\"args\":[\"1\"")){
//                        cipher_init=true;
//                    }else if(line.contains("\"class\":\"java.io.FileOutputStream\"") && line.contains("\"method\":\"java.io.FileOutputStream\"")){
//                        fileoutputstream=true;
//                    }
                }
                instream.close();
            }
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
        boolean flag=cipher_getinstance && cipher_init && fileoutputstream;
        return flag;
    }






}
