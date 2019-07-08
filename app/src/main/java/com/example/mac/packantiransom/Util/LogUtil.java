//package com.example.mac.packantiransom.Util;
//
//import android.util.Log;
//import android.widget.Toast;
//
//
//import com.alibaba.fastjson.JSONArray;
//import com.alibaba.fastjson.JSONObject;
//
//import java.io.BufferedReader;
//import java.io.DataOutputStream;
//import java.io.IOException;
//import java.io.InputStreamReader;
//import java.util.ArrayList;
//import java.util.HashMap;
//import java.util.List;
//import java.util.Map;
//
//public class LogUtil {
//    ArrayList<String> LogMessage=new ArrayList<>();
//    ArrayList<String> applications=new ArrayList<>();
//    /**    cipher_FileOutStream的每两个元素作为一组，代表一个应用是否使用了cipher.init(1,key,iv)与FileOutStream   */
////    Boolean[] cipher_FileOutStream=new Boolean[]{false,false,false,false,false,false,false,false,false,false};//假定被hook到的应用最多5个
//
////    Map<String,Integer> Map_iv= new HashMap<>(); // key:app_packagename,value:iv_value
////    Map<String,String> Map_Cipher_getInstance=new HashMap<>(); // key:app_packagename,value:Cipher_getInstance
//    ArrayList<JSONObject> KEY_ARRAY;
//    ArrayList<JSONObject> IV_ARRAY;
//    ArrayList<String> getInstance_ARRAY;
//    Map<String,String> file_app=new HashMap<>();// key:filePath,value:appPackage
//
//
//    public void dealLog(){
////        select_appReadFils();// 在日志中搜索"应用P读A.doc文件"的信息
////        select_appAES();//在日志中搜索"应用A调用了加密操作"的信息
//        selectHookLog();
//        /***    applications中此时保存的，是同时使用cipher.init(1,key,iv)与FileOutStream的应用*/
//        if(applications.size()==0){
//            // 这里先不做什么，过后再处理。2019.4.28
//        }
//        else if(applications.size()==1){
////            selectParams(0);
//
//        }else if(applications.size()>1){
//
//        }
//
//    }
//
//
////    public void selectParams(int index){
////        String pkgName=applications.get(index);
////        String tmpName;
////        ArrayList<String> fileList=new ArrayList<>();
////        String tmpFileName;
////        String iv;
////        String cipher_alg;
////        String key_key;
////        String key_algorithm;
////        for(int i=0;i<LogMessage.size();i++){
////            String line=LogMessage.get(i);
////            tmpName=line.replace("(","-").split("-")[2];
////            if(tmpName.equals(pkgName)){
//
////                if(line.contains(keyStrings[0])&& line.contains(keyStrings[1]) &&line.contains(keyStrings[2])){//"class":"javax.crypto.Cipher","method":"init"
////                    key_key=line.split("\"key\":")[1].split(",\"algorithm\"")[0];// [......]
////                    key_key=key_key.substring(1,key_key.length());
////                    key_algorithm=line.split("\"algorithm\"")[1];
////                    key_algorithm=key_algorithm.substring(2,key_algorithm.indexOf("\"}"));
////                    iv=line.split("\"iv\"")[1];
////                    iv=iv.substring(2,iv.indexOf("]}"));
////                    Log.i("shenlala_key_key",key_key);
////                    Log.i("shenlala_key_algorithm",key_algorithm);
////                    Log.i("shenlala_iv",iv);
//////                }
//////                if(line.contains(keyWord[0]) && line.contains(keyWord[1])){// "class":"javax.crypto.spec.IvParameterSpec","method":"IvParameterSpec"
//////                    iv=Integer.valueOf(line.substring(line.lastIndexOf("byte-length")+14,line.lastIndexOf("\"}")));
//////                    Log.i("shenlala_iv",String.valueOf(iv));
//////                }
//////                else if(line.contains(keyWord[2])&& line.contains(keyWord[3])){ //"class":"javax.crypto.Cipher","method":"getInstance"
//////                    cipher_alg=line.split("\"transformation\":\"")[1].split("\"")[0];
//////                    Log.i("shenlala_cipher_alg",cipher_alg);
//////                }else if(line.contains(keyWord[4])&& line.contains(keyWord[5]) && line.contains(keyWord[6])){// "class":"javax.crypto.Cipher","method":"init"
//////                    key_decoded=line.split("key-encode\":\"")[1].split("\"")[0];
//////                    key_alg=line.split("\"key-algorithm\":\"")[1].split("\"")[0];
//////
//////                    Log.i("shenlala_key_decoded",key_decoded);
//////                    Log.i("shenlala_key_alg",key_alg);
////                }else if(line.contains(keyStrings[3])&& line.contains(keyStrings[4])){//"class":"java.io.FileOutputStream","method":"FileOutputStream"
////                    tmpFileName=line.split("\"args\"")[1];
////                    tmpFileName=tmpName.substring(3,tmpFileName.length()-2);
////                    if(!fileList.contains(tmpFileName)){
////                        fileList.add(tmpFileName);
////                        Log.i("shenlala_fileList",tmpFileName);
////                    }
////                }
////            }
////        }
////
////
////
////    }
//
//
//
//    public void selectHookLog(){
//        Process process=null;
//        InputStreamReader is;
//        BufferedReader bufferedReader;
//        String line;
//        String appName;
//        int Index_app;
//        try {
//            process=Runtime.getRuntime().exec(new String[]{"sh","-c","logcat | grep apimonitor"});
////            process.waitFor();
////            DataOutputStream stdin = new DataOutputStream(process.getOutputStream());
////            stdin.writeBytes("logcat | grep apimonitor");
//            is=new InputStreamReader(process.getInputStream());
//            bufferedReader=new BufferedReader(is);
//            /**  提取log日志保存到LogMessage,并获取相关的应用包名（可能存在多个应用)**/
//            String tmp;
//            String qianzhui;
//            JSONObject jsStr;
//            String classname;
//            String methodname;
//            JSONArray args;
//            String arg_0;
//            JSONObject key;
//            JSONObject iv;
//            String file;
//            JSONArray ja;
//            while ((line=bufferedReader.readLine())!=null){
////                if((!line.contains("beforehook"))&&(!line.contains("afterhook"))){
//                    qianzhui=line.split(":")[0];
////                    tmp=line.replace("(","-");
////                    appName=tmp.split("-")[2];
//                    tmp=qianzhui.replace("(","-");
//                    appName=tmp.split("-")[2];
//                    if(!appName.equals("com.example.mac.packantiransom")){
//                        LogMessage.add(line);
//                        if(!applications.contains(appName)){
//                            applications.add(appName);
//                        }
//
//                        jsStr = JSONObject.parseObject(line.substring(qianzhui.length()+2));
//                        classname=jsStr.getString("class");
//                        methodname=jsStr.getString("method");
//                        args=jsStr.getJSONArray("args");
//
//                        if(classname.equals("javax.crypto.Cipher")&& methodname.equals("init")){
//                            arg_0=args.getString(0);
//                            if((arg_0.equals("1"))){
//                                Index_app=applications.indexOf(appName);
//                                key=args.getJSONObject(1);
//                                KEY_ARRAY.add(Index_app,key);
//                                iv=args.getJSONObject(2);
//                                IV_ARRAY.add(Index_app,iv);
//                            }
//                        }
//                        else if (classname.equals("java.io.FileOutputStream")&&methodname.equals("java.io.FileOutputStream")){
////                            Index_app=applications.indexOf(appName);
////                            cipher_FileOutStream[Index_app*2+1]=true;
////                            ja=args.getJSONArray(0);
//                            file=args.getString(0);
//                            file_app.put(file,appName);
//                        }
//                        else if(classname.equals("javax.crypto.Cipher")&&methodname.equals("getInstance")){
//                            arg_0=args.getString(0);
//                            Index_app=applications.indexOf(appName);
//                            getInstance_ARRAY.add(Index_app,arg_0);
//                        }
//                    }
//                }
//                bufferedReader.close();
//
////            }
////            /**   针对每个应用，看其对应的cipher_FileOutStream的两个值。若有其中一个值为false，则将该应用从applications中删除**/
////            for(int x=applications.size()-1;x>=0;x--){
////                if((!cipher_FileOutStream[x*2+1]) | (!cipher_FileOutStream[x*2])){
////                    applications.remove(x);
////                }
////            }
//        } catch (IOException e) {
//            e.printStackTrace();
//        }
//    }
//
//    /***
//    public void select_appReadFils(){
//        String cmd="logcat | grep hookAntiRansom | grep \"method\":\"FileInputStream\"";
//        Process process = null;
//        InputStreamReader is;
//        BufferedReader bufferedReader;
//        String line;
//        String prog;
//        String newLog;
//        String timeStamp;
//        String fileName;
//        try {
//            process = Runtime.getRuntime().exec(cmd);
//            is=new InputStreamReader(process.getInputStream()) ;
//            bufferedReader= new BufferedReader(is);
//            while ((line = bufferedReader.readLine()) != null) {
//                prog=line.substring(22,line.indexOf("("));
//                timeStamp=line.substring(line.indexOf("{\"timestamp\":")+13,line.indexOf(",\"class\":"));
//                fileName=line.substring(line.indexOf("\"args\":[{\"path\":")+17,line.lastIndexOf("\"}]}"));
//                newLog="timeStamp:"+timeStamp+"_progress:"+prog+"_fileName:"+fileName;
//                appReadFils.add(newLog);
//            }
//            is.close();
//            bufferedReader.close();
//        }catch (IOException e) {
//            e.printStackTrace();
//        }
//    }
//
//    public void select_appAES(){
//        select_cipher();
//
//         * 注意！！！这里还得获取cipher.init第二个参数key的各种数值
//         *
//         *
//         * select_key();
//         select_iv();
//
//
//
//
//    }
//
//    public void select_cipher(){
//        String cmd="logcat | grep hookAntiRansom | grep Cipher | getInstance";
//        Process process = null;
//        InputStreamReader is;
//        BufferedReader bufferedReader;
//        String line;
//        String prog;
//        String newLog;
//        String timeStamp;
//        String cipherArgs;
//        try {
//            process = Runtime.getRuntime().exec(cmd);
//            is=new InputStreamReader(process.getInputStream()) ;
//            bufferedReader= new BufferedReader(is);
//            while ((line = bufferedReader.readLine()) != null) {
//                prog=line.substring(22,line.indexOf("("));
//                timeStamp=line.substring(line.indexOf("{\"timestamp\":")+13,line.indexOf(",\"class\":"));
//                cipherArgs=line.substring(line.indexOf("\"crypto\",\"args\":[")+17,line.lastIndexOf("\"]}"));
//                newLog="timeStamp:"+timeStamp+"_progress:"+prog+"_cipherArgs:"+cipherArgs;
//                appCipher.add(newLog);
//            }
//            is.close();
//            bufferedReader.close();
//        }catch (IOException e) {
//            e.printStackTrace();
//        }
//    }
//
//    public void select_key(){
//
//    }
//
//    public void select_iv(){
//
//    }
//    */
//
//}
