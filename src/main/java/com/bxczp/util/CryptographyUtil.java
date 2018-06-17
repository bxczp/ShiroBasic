package com.bxczp.util;

import org.apache.shiro.codec.Base64;
import org.apache.shiro.crypto.hash.Md5Hash;

/**
 * shiro 的加密解密
 * 
 * @author bxczp
 *
 */
public class CryptographyUtil {

    /**
     * base64加密
     * 
     * @param str
     * @return
     */
    public static String encBase64(String str) {
        return Base64.encodeToString(str.getBytes());
    }

    /**
     * base64解密
     * 
     * @param str
     * @return
     */
    public static String decBase64(String str) {
        return Base64.decodeToString(str);
    }

    /** 
     * 
     *强推 MD5 加密 不可逆 无法解析出原数据
     * Md5加密
     * 
     * @param str 要加密的数据
     * @param salt 平衡量
     * @return
     */
    public static String md5(String str, String salt) {
        return new Md5Hash(str, salt).toString();
    }

    public static void main(String[] args) {
        String password = "123456";
        System.out.println("Base64加密：" + CryptographyUtil.encBase64(password));
        System.out.println("Base64解密：" + CryptographyUtil.decBase64(CryptographyUtil.encBase64(password)));

        System.out.println("Md5加密：" + CryptographyUtil.md5(password, "java1234"));
    }
}
