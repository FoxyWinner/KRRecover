package com.example.mac.packantiransom.modelDetect.Util;

import android.content.Context;
import android.util.Log;



import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.OutputStream;

public class FeaturesUtil {
    /***
    public static String[] a_读取apipackagelist到应用目录下(String arg3, Context arg4) throws IOException, ClassNotFoundException {
        StringBuilder v1 = new StringBuilder();
        v1.append(arg4.getFilesDir());
        v1.append("/");
        v1.append(arg3);
        if(!new File(v1.toString()).exists()) {
            FeaturesUtil.a(arg4, arg3, FeaturesUtil.a(arg4));
        }

        FileInputStream v3 = arg4.openFileInput(arg3);
        ObjectInputStream v4 = new ObjectInputStream(((InputStream)v3));
        Object v0 = v4.readObject();
        v3.close();
        v4.close();
        return ((String[])v0);
    }

    private static String[] a(Context arg3) throws IOException {
        String[] v0 = new String[270];
            BufferedReader v1 = new BufferedReader(new InputStreamReader(arg3.getResources().openRawResource(2131689472)));
            int v3_2;
            for(v3_2 = 0; true; ++v3_2) {
                String v2 = v1.readLine();
                if(v2 == null) {
                    break;
                }
                v0[v3_2] = v2;
            }
            v1.close();
        return v0;
    }

    private static void a(Context arg2, String arg3, String[] arg4) {
        try {
            FileOutputStream v2_1 = arg2.openFileOutput(new File(arg2.getFilesDir(), arg3).getName(), 0);
            ObjectOutputStream v3 = new ObjectOutputStream(((OutputStream)v2_1));
            v3.writeObject(arg4);
            v3.flush();
            v2_1.getFD().sync();
            v3.close();
            v2_1.close();
            return;
        }
        catch(IOException v2) {
            v2.printStackTrace();
            return;
        }
    }
    static float[] A(HashMultiset arg5, String[] arg6) {
        float[] v0 = new float[271];
        Log.i("Extractfeatures", "Features counting");
        if(arg6 != null) {
            int v1 = arg6.length;
            int v2 = 0;
            int v3 = 0;
            while(v2 < v1) {
                v0[v3] = ((float)arg5.A(arg6[v2]));
                ++v3;
                ++v2;
            }

            v0[v3] = 92f;
        }

        Log.i("Extractfeatures", "Features counted");
        return v0;
    }
     ***/
}
