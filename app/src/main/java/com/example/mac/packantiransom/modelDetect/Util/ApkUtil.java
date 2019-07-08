package com.example.mac.packantiransom.modelDetect.Util;

import android.content.Context;
import android.content.pm.PackageManager;
import android.util.Log;

import org.jf.dexlib2.DexFileFactory;
import org.jf.dexlib2.dexbacked.DexBackedDexFile;
import org.jf.dexlib2.dexbacked.reference.DexBackedStringReference;
import org.jf.dexlib2.iface.ClassDef;
import org.jf.dexlib2.iface.DexFile;
import org.jf.dexlib2.iface.Method;
import org.jf.dexlib2.iface.MultiDexContainer;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Set;

import lanchon.multidexlib2.EmptyMultiDexContainerException;

//import org.jf.dexlib2.iface.DexFile;


/*** 该类用于对dex文件进行分析，提取API package*/
public class ApkUtil {
//    private static boolean a = false;






    /***
    static HashMultiset B(String arg6, Context arg7, boolean arg8) {
     ***/
    /*** 方法B： 用于对arg6所示软件进行dex分析，获取API package信息*/
    static DexFile getDexFile(String arg6) {
        lanchon.multidexlib2.MultiDexContainerBackedDexFile v6_2;
        lanchon.multidexlib2.SingletonDexContainer v3_2;
        File v2;
        DexFile v1=null;
        try {
            v2 = new File(arg6);
            lanchon.multidexlib2.BasicDexFileNamer v6_1 = new lanchon.multidexlib2.BasicDexFileNamer();
            if(v2.isDirectory()) {
                lanchon.multidexlib2.DirectoryDexContainer v3 = new lanchon.multidexlib2.DirectoryDexContainer(v2, ((lanchon.multidexlib2.DexFileNamer)v6_1),null);
                if(((MultiDexContainer)v3).getDexEntryNames().size() == 0) {
                    throw new EmptyMultiDexContainerException(v2.toString());
                }
                v6_2 = new lanchon.multidexlib2.MultiDexContainerBackedDexFile(((MultiDexContainer)v3));
            }
            else if(!v2.isFile()) {
                throw new FileNotFoundException(v2.toString());
            }
            else if(lanchon.multidexlib2.ZipFileDexContainer.isZipFile(v2)) {
                lanchon.multidexlib2.ZipFileDexContainer v3_1 = new lanchon.multidexlib2.ZipFileDexContainer(v2, ((lanchon.multidexlib2.DexFileNamer)v6_1),null);
                if(((MultiDexContainer)v3_1).getDexEntryNames().size() == 0) {
                    throw new EmptyMultiDexContainerException(v2.toString());
                }
                v6_2 = new lanchon.multidexlib2.MultiDexContainerBackedDexFile(((MultiDexContainer)v3_1));// 03.21 在这里出问题啦
            }
            else {
                v3_2 = new lanchon.multidexlib2.SingletonDexContainer(lanchon.multidexlib2.RawDexIO.readRawDexFile(v2,null));
                if(((MultiDexContainer)v3_2).getDexEntryNames().size() == 0) {
                    throw new EmptyMultiDexContainerException(v2.toString());
                }
                v6_2 = new lanchon.multidexlib2.MultiDexContainerBackedDexFile(((MultiDexContainer)v3_2));
            }
        }
        catch(Exception v6) {
            Log.i("Error!!",v6.getMessage());
            return v1;
        }
//        return ApkUtil.getMethods(((DexFile)v6_2));
        return v6_2;
    }



            /***
            v0.addAll(StreamSupport.stream(Spliterators.A_哪呢(Lists.a(v3_1.next().b()))).a(
            public final Object apply(Object arg1) {
                return ApkUtil.lambda$MOdgAO6U-wBuYmzh5I0C57zfrXQ(((Method)arg1));
            }

            ).a(
            public final boolean test(Object arg1) {
                return ApkUtil.lambda$L0C1mfk2Npf1tim7TZfD5c5dvXI(((MethodImplementation)arg1));
            }
            ).b(
            public final Object apply(Object arg1) {
                return ApkUtil.lambda$uALCV-DVZUfhM94GVcUBIFWmMTY(((MethodImplementation)arg1));
            }
            ).a(
            public final boolean test(Object arg1) {
                return ApkUtil.lambda$0DKJgam63OsRHbQkZAHWkA8yoqk(((f)arg1));
            }
            ).a(
            public final Object apply(Object arg1) {
                return ApkUtil.lambda$wOz4hwII560S0Gggx_IqMIanyQo(((f)arg1));
            }
            ).a(
            public final boolean test(Object arg1) {
                return ApkUtil.lambda$TPNkF9oVOlo6IyAGu74CfbsONxY(((ReferenceInstruction)arg1));
            }
            ).a(
            public final Object apply(Object arg1) {
                return ((ReferenceInstruction)arg1).b();
            }
            ).a(
                    public final Object apply(Object arg1) {
                return ApkUtil.lambda$ua2AkPey7kHXnbondmBKHW29dL8(((Reference)arg1));
            }).a(
            public final boolean test(Object arg1) {
                return ApkUtil.lambda$CNC9sEVRAL-1OAROf7IM-9nKhBg(((MethodReference)arg1));
            }
            ).a(
            public final Object apply(Object arg1) {
                return ApkUtil.lambda$UE2GVsENldc84MZ5QQGykP8qxzw(((MethodReference)arg1));
            }
            ).a(Collectors.a()));
        ***/
    public static ArrayList getMethods(DexFile arg2) {
        try {
            ArrayList methodsName = new ArrayList();
            String c_m=null;
            for(ClassDef classdef :arg2.getClasses()){
                for (Method m:classdef.getMethods()){
//                    c_m=m.getClass().getName();
                    c_m=m.getDefiningClass();
                    c_m=c_m+"->"+m.getName();
                    methodsName.add(c_m);
                }

            }
            return methodsName;
        }
        catch(OutOfMemoryError v2) {
            return null;
        }
    }

    public static ArrayList<String> getClasses(DexFile arg2) {
        try {
            ArrayList<String> classesName = new ArrayList<>();
            String c_m=null;
            String[] c=null;
            String pkg=null;
            for(ClassDef classdef :arg2.getClasses()){
                for (Method m:classdef.getMethods()){
//                    c_m=m.getClass().getName();
                    c_m=m.getDefiningClass();
                    c=c_m.split("/");
                    if(c_m.contains("com/baidu") || c_m.contains("com/google") || c_m.contains("com/facebook") || c_m.contains("com/qq")){
                        pkg=c[0]+"."+c[1]+"."+c[2];
                    }
                    else {
                        if(c.length>=2){
                            pkg=c[0]+"."+c[1];
                        }
                        else {
                            pkg=c[0];
                        }
                    }
                    if(!classesName.contains(pkg)){
                        classesName.add(pkg);
                    }
                }
            }
            return classesName;
        }
        catch(OutOfMemoryError v2) {
            return null;
        }
    }
/***
    private static HashMultiset C(DexFile arg3) {
    ***/
    private static Set C(DexFile arg3) {
//        HashMultiset v0 = HashMultiset.e();
        /***
        HashMultiset v0 = HashMultiset.create();
         */
        Set v0=null;
        try {
            Iterator v3_1 = arg3.getClasses().iterator();
            while(v3_1.hasNext()) {
//                v0.addAll(StreamSupport.stream(Spliterators.a(Lists.a(v3_1.next().b()))).a(lambda_F.INSTANCE).a(lambda_E.INSTANCE).b(lambda_N.INSTANCE).a(lambda_B.INSTANCE).a(lambda_P.INSTANCE).a(lambda_G.INSTANCE).a(lambda_S.INSTANCE).a(lambda_O.INSTANCE).a(lambda_D.INSTANCE).a(lambda_H.INSTANCE).a(Collectors.a()));
                v0.addAll((Collection)v3_1.next());
            }
        }
        catch(OutOfMemoryError v3) {
            return null;
        }
        return v0;
        }
}
