package com.example.mac.packantiransom.modelDetect.Util;

import android.content.Context;

import com.alibaba.fastjson.JSONObject;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;

public class FeatureToVectorUtil {
    /***
     * 对提取的特征进行数值化处理，从而生成可供机器学习的数组
     */
//    private static String[] attributeKeyKindOne = {"activities", "services", "permList", "intents_in_code",
//            "nameList", "pkgList", "potential_misBhve"};
//    private static String[] attributeKeyKindTwo = {"APIsList", "cmdList", "keywordsListEqual", "keywordsListIn"};

            /****    300维特征
    private static String[] attributeKeyKindString = {"receiver_priority","app_name_language"};
    private static String[] attributeKeyKindFloat = {"package_name_shannon","fileSize"};
    private static String[] attributeKeyKindMapOne = {"cmdList","APIsList","keywordsListIn","keywordsListEqual"};
    private static String[] attributeKeyKindArrayListOne = {"activities","services","permList","intents_in_code","nameList","pkgList","potential_misBhve"};
    private static String[] attributeKeyKindArrayListTwo = {"urlList","phoneList","emailList"};
    private static String[] attributeKeyKindInt = {"potential_misBhve_cnt"};
    private static String[] attributeKeyKindBoolen = {"hasVideo","hasHTMLDocuments","hasFakeInstaller3or4Files"};
*/


    public ArrayList<String> allfeatures = new ArrayList<String>();
    public FeatureToVectorUtil(Context context){
        try {
            InputStreamReader inputReader = new InputStreamReader(context.getAssets().open("ransomFeatureSet.txt") );
            BufferedReader bufReader = new BufferedReader(inputReader);
            String line="";
            ArrayList<String> Result = new ArrayList<>();
            int i = 0;
            while((line = bufReader.readLine()) != null)
                Result.add(line);
            i++;
            this.allfeatures = Result;
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public ArrayList<Float> generateVectorUtil(String arg6, String pkgName,String appName,Context arg5){
        extractFeature featuraAll=new extractFeature(arg6, pkgName,appName,arg5);

        System.out.println(featuraAll.getFeature());
        ArrayList<Float> fvector = new ArrayList<>();
        int count_zero=0;
        for (String feature:allfeatures) {
            if(feature == "app_name_language"){
                if(featuraAll.app_name_language=="ru"){
                    fvector.add((float) 1);
                    continue;
                }
            }
            else if(feature == "package_name_shannon"){
                fvector.add(featuraAll.package_name_shannon);
                continue;
            }
            else if(feature == "filesize"){
                fvector.add(featuraAll.fileSize);
                continue;
            }
            else if(featuraAll.cmdList.containsKey(feature)){
                fvector.add(Float.valueOf(featuraAll.cmdList.get(feature)));
                continue;
            }
            else if(featuraAll.APIsList.containsKey(feature)){
                fvector.add(Float.valueOf(featuraAll.APIsList.get(feature)));
                continue;
            }
            else if(featuraAll.keywordsListIn.containsKey(feature)){
                fvector.add(Float.valueOf(featuraAll.keywordsListIn.get(feature)));
                continue;
            }
            else if(featuraAll.keywordsListEqual.containsKey(feature)){
                fvector.add(Float.valueOf(featuraAll.keywordsListEqual.get(feature)));
                continue;
            }
            else if(featuraAll.activities.contains(feature)){
                fvector.add((float) 1);
                continue;
            }
            else if(featuraAll.services.contains(feature)){
                fvector.add((float) 1);
                continue;
            }
            else if(featuraAll.permList.contains(feature)){
                fvector.add((float) 1);
                continue;
            }
            else if(featuraAll.intents_in_code.contains(feature)){
                fvector.add((float) 1);
                continue;
            }
            else if(featuraAll.nameList.contains(feature)){
                fvector.add((float) 1);
                continue;
            }
            else if(featuraAll.pkgList.contains(feature)){
                fvector.add((float) 1);
                continue;
            }
            else if(featuraAll.potential_misBhve.contains(feature)){
                fvector.add((float) 1);
                continue;
            }

            else if(feature == "urlList"){
                fvector.add((float)(featuraAll.urlList.size()));
                continue;
            }
            else if(feature == "phoneList"){
                fvector.add((float)(featuraAll.phoneList.size()));
                continue;
            }
            else if(feature == "emailList"){
                fvector.add((float)(featuraAll.emailList.size()));
                continue;
            }

            else if(feature == "potential_misBhve_cnt"){
                fvector.add(Float.valueOf(featuraAll.potential_misBhve_cnt));
                continue;
            }

            else if(feature == "hasVideo"){
                if(featuraAll.hasVideo == Boolean.TRUE){
                    fvector.add((float)(1));
                    continue;
                }
            }
            else if(feature == "hasHTMLDocuments"){
                if(featuraAll.hasHTMLDocuments == Boolean.TRUE){
                    fvector.add((float)(1));
                    continue;
                }
            }
            else if(feature == "hasFakeInstaller3or4Files"){
                if(featuraAll.hasFakeInstaller3or4Files == Boolean.TRUE){
                    fvector.add((float)(1));
                    continue;
                }
            }
            fvector.add((float)0);
            count_zero+=1;
        }
        System.out.println(count_zero);
        return fvector;
    }





/**
    public ArrayList<Float> generateVectorUtil(String json){
        ArrayList<Float> fvector = new ArrayList<>();
        JSONObject data = JSONObject.parseObject(json);
        JSONObject data2 = JSONObject.parseObject(data.getString("attribute"));
        for (String feature:allfeatures) {
            int flag = 1;
            for(String attributeone: attributeKeyKindOne){
                if (data2!=null && data2.containsKey(attributeone)){
                    String temp = data2.getString(attributeone);
                    if(temp == feature){
                        fvector.add((float) 1);
                        flag = 0;
                        break;
                    }
                }
            }
            if (flag == 0){
                continue;
            }
            for(String attributetwo: attributeKeyKindMapOne) {
                JSONObject data_3 = JSONObject.parseObject(data2.getString(attributetwo));
                Map<String,Integer> data3 =(Map<String, Integer>)data_3;
                if (data3!=null && data3.containsKey(feature)) {
                    fvector.add(data3.getFloat(feature));
                    flag = 0;
                    break;
                }
            }
            if (flag == 0){
                continue;
            }
            if(feature == "filesize"){
                fvector.add(data2.getFloat("filesize"));
                continue;
            }
            if(feature == "package_name_shannon"){
                fvector.add(data2.getFloat("package_name_shannon"));
                continue;
            }
            if(feature == "phoneList"){
                fvector.add((float)(data2.getString("phoneList")).length());
                continue;
            }
            if(feature == "emailList"){
                fvector.add((float)(data2.getString("emailList")).length());
                continue;
            }
            if(feature == "urlList"){
                fvector.add((float)(data2.getString("urlList")).length());
                continue;
            }
            if(feature == "hasVideo"){
                Boolean data3 = data2.getBoolean("hasVideo");
                if(data3 == Boolean.TRUE){
                    fvector.add((float)(1));
                    continue;
                }
            }
            if(feature == "hasFakeInstaller3or4Files"){
                Boolean data3 = data2.getBoolean("hasFakeInstaller3or4Files");
                if(data3 == Boolean.TRUE){
                    fvector.add((float)(1));
                    continue;
                }
            }
            if(feature == "hasHTMLDocuments"){
                Boolean data3 = data2.getBoolean("hasHTMLDocuments");
                if(data3 == Boolean.TRUE){
                    fvector.add((float)(1));
                    continue;
                }
            }
            if(feature == "potential_misBhve_cnt"){
                JSONObject data3 = JSONObject.parseObject(data2.getString("potential_misBhve_cnt"));
                fvector.add(data3.getFloat("reflect_cnt"));
            }
            if(feature == "app_name_language"){
                String data3 = data2.getString("language");
                if(data3 == "ru"){
                    fvector.add((float) 1);
                    continue;
                }
            }
            Map<String, String> map = new HashMap<String, String>();
            JSONObject data3 = JSONObject.parseObject(data2.getString("receiver_priority"));
            if(data3!=null){
                Iterator<String> keys = data3.keySet().iterator();
                while (keys.hasNext()) {
                    String key = keys.next();
                    String[] temp = key.split("___");
                    for (String t1:temp) {
                        String l = t1 + "_priority";
                        map.put(l, data3.getString(key));
                    }
                }
            }

            if(map!=null && map.containsKey(feature)){
                if((map.get(feature).split("0x")).length>1){
                    fvector.add((float)Long.parseLong(map.get(feature), 16));
                }
                else{
                    fvector.add((float)(Integer.valueOf(map.get(feature),10)));
                }
                continue;
            }
            fvector.add((float)0);
        }
        return fvector;
    }
 */
}
