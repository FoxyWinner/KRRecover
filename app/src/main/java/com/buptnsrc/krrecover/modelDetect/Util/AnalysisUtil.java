package com.buptnsrc.krrecover.modelDetect.Util;

import android.content.Context;


import com.buptnsrc.krrecover.R;

import org.tensorflow.contrib.android.TensorFlowInferenceInterface;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.Arrays;


public class AnalysisUtil {

    /**** 用于临时测试步骤3 ，读取某软件的检测结果（即特征文件），*/
    public static String readCSV(Context arg4) {
        String v0="" ;
        try {
            BufferedReader v1 = new BufferedReader(new InputStreamReader(arg4.getResources().openRawResource(R.raw.ransom)));
            String features = v1.readLine();// 特征，也就是第一行标题啦
            v0 = v1.readLine();
            v1.close();
        }
        catch(IOException v4) {
            v4.printStackTrace();
        }
        return v0;
    }

    private static String b(int[] arg2) {
        String v2 = Arrays.toString(arg2);
        return v2.substring(1, v2.length() - 1);
    }
    /***
    public static Bundle 对参数2的应用进行API分析并返回分析结果(Context arg5, String arg6, String[] arg7) {
     ***/
    /*** 步骤1的话，这样就可以了
    public static Set 对参数2的应用进行API分析并返回分析结果(Context arg5, String arg6) {
     */
    /** 对arg6所示软件进行dex分析，并用模型判断其作为勒软的可能性**/
    public static int 对参数2的应用进行API分析并返回分析结果(Context arg5, String arg6,String pkgName,String appName) throws IOException {
                                        //this.getApplicationContext(), 待分析应用的sourceDir,待分析应用的包名,待分析应用的应用名称
        long v1 = System.nanoTime();

        // 暂时先返回 hashmultiset
        /***  步骤1到下面这一步就完成啦，即完成了对某一软件的dex文件分析***/
//        extractFeature featuraAll=new extractFeature(arg6, pkgName,appName,arg5);
//        String feature=featuraAll.getFeature();
//        System.out.println(feature);

        FeatureToVectorUtil f=new FeatureToVectorUtil(arg5);
        ArrayList<Float> fvector= f.generateVectorUtil(arg6, pkgName,appName,arg5);

        if(1==1){
            InputStream is=arg5.getResources().openRawResource(R.raw.originalheldroid);
            /** 下面使用的是R-PackDroid原用的tensorFloe**/
//            Bundle v2_1 = new Bundle();
            try{
                System.loadLibrary("tensorflow_inference");
//                TensorFlowInferenceInterface v7 = new TensorFlowInferenceInterface(arg5.getAssets(), "file:///android_asset/rpackdroid_optimised_model.pb");
                TensorFlowInferenceInterface v7 = new TensorFlowInferenceInterface(arg5.getAssets(), "file:///android_asset/300w.pb");
                int size=fvector.size();
                float[] v6_1=new float[size];

                for(int x=0;x<size;x++){
                    v6_1[x]=fvector.get(x);
                }
                v7.feed("x_input", v6_1, 1,300);
                v7.run(new String[]{"output"});
                int[] v0_1 = new int[1];
                v7.fetch("output", v0_1);// 模型检测出来的结果放到v0_1中
//                int v7_1 = AnalysisUtil.indexOfMaxVelua(v0_1);
//                v2_1.putString("App",arg6);
//                v2_1.putInt("AA_RESULT", v7_1); //
//                v2_1.putString("AA_PROBABILITIES", AnalysisUtil.b(v0_1)); //
                return v0_1[0]; //这里先只获取结果的PROBABILITIES
//            v1_1.putStringArrayList("MOSTCALLED", AnalysisUtil.a(arg5, v6_1));
//                return v2_1;

            } catch (Exception e){
                return 1;// 这里先默认设置为0.5，即可疑应用
            }

/****       下面使用的是xgboost的方法

//            java.io.FileInputStream fis=(java.io.FileInputStream)is;
            Predictor predictor=new Predictor(is);
            FVec fVecDense = FVec.Transformer.fromArray(
                    denseArray,
                    true );
            // Create feature vector from sparse representation by map
            FVec fVecSparse = FVec.Transformer.fromMap(
                    new java.util.HashMap<Integer, Double>() {{
                        put(2, 32.);
                        put(5, 16.);
                        put(6, -8.);
                    }});
            // Predict probability or classification
            float[] prediction = predictor.predict(fVecDense);
            // prediction[0] has
            //    - probability ("binary:logistic")
            //    - class label ("multi:softmax")

            // Predict leaf index of each tree
            int[] leafIndexes = predictor.predictLeaf(fVecDense);
            // leafIndexes[i] has a leaf index of i-th tree
 */
        }
        return 1;
    }

    private static int indexOfMaxVelua(float[] arg6) {
//        int v0 = Floats.a(arg6, Floats.a(arg6));
        int v0=0;
        float max=arg6[0];
        int index=0;
        for ( v0 = 0; v0 < arg6.length; v0++) {
            if(arg6[v0]>max){
                index=v0;
                max=arg6[0];
            }
        }
        if(index == 1 && arg6[0] > arg6[2] && (((double)arg6[1])) <= 0.86) {
            index = 0;
        }
        return index;
    }

        /***
    private static String b(float[] arg2) {
        String v2 = Arrays.toString(arg2);
        return v2.substring(1, v2.length() - 1);
    }
    private static ArrayList a(Context arg7, float[] arg8) {
        String[] v7_1;
        ArrayIndexComparator v0 = new ArrayIndexComparator(arg8);
        Integer[] v1 = new Integer[v0.a.length];
        int v2 = 0;
        int v3;
        for(v3 = 0; v3 < v0.a.length; ++v3) {
            v1[v3] = Integer.valueOf(v3);
        }

        Arrays.sort(((Object[])v1), ((Comparator)v0));
        Collections.reverse(Arrays.asList(((Object[])v1)));
        ArrayList v0_1 = new ArrayList();
        String[] v3_1 = null;
        int v4 = 2131755058;
        try {
            v7_1 = FeaturesUtil.a_读取apipackagelist到应用目录下(arg7.getString(v4), arg7);
        }
        catch(ClassNotFoundException v7) {
            ((Exception)v7).printStackTrace();
            v7_1 = v3_1;
        }

        v3 = v1.length;
        while(v2 < v3) {
            v4 = v1[v2].intValue();
            if(v4 < 270 && arg8[v4] != 0f) {
                v0_1.add(v7_1[v4]);
            }

            ++v2;
        }

        return v0_1;
    }
         */


    /***
     public static HashMap a_获取raw目录下某文件内容并保存成HashMap格式(Context arg4) throws IOException {
     HashMap v0 = new HashMap();
     BufferedReader v1 = new BufferedReader(new InputStreamReader(arg4.getResources().openRawResource(2131689473)));
     while(true) {
     String v4_2 = v1.readLine();
     if(v4_2 == null) {
     break;
     }
     String[] v4_3 = v4_2.split(":");
     v0.put(v4_3[0], Integer.valueOf(v4_3[1]));
     }

     v1.close();
     return v0;
     }
     ***/



}


