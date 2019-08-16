package action.order.util;

import java.util.Random;

import org.apache.commons.lang.ArrayUtils;
import org.apache.commons.lang.RandomStringUtils;

/**
 * @ClassName: GenerateKeyUtils
 * @Description:TODO
 * @author: ZWC
 * @date: 2019-8-16 上午9:54:16
 */
public class GenerateKeyUtils {
    private static final int PRIVATE_KEY_LENGTH = 1024;
    private static final int PUBLIC_KEY_LENGTH = 2048;

    private volatile static GenerateKeyUtils instance;

    private GenerateKeyUtils() {
    }

    public static GenerateKeyUtils getDefault() {
        if (instance == null) {
            synchronized (GenerateKeyUtils.class) {
                if (instance == null) {
                    instance = new GenerateKeyUtils();
                }
            }
        }
        return instance;
    }

    public String getSign(int code) {
        Random ran = new Random(code);
        StringBuilder sb = new StringBuilder();
        for (int j = 0; j < 16; j++) {
            sb.append((char) ('`' + ran.nextInt(26) + 1));
        }
        return sb.toString();
    }

    public boolean checkSign(int code, String key) {
        String sign = getSign(code);
        return sign.equals(invokeSign(key));
    }

    public boolean checkSign(int code, String key, boolean randomIndex) {
        String sign = getSign(code);
        if (randomIndex) {
            return sign.equals(invokeSign(code, key));
        }
        return sign.equals(invokeSign(key));
    }

    public boolean checkKey(String publickKey, String privateKey) {
        return invokeSign(publickKey).equals(invokeSign(privateKey));
    }

    public boolean checkKey(int code, String publickKey, String privateKey,
            boolean randomIndex) {
        if (randomIndex) {
            return invokeSign(code, publickKey).equals(invokeSign(code, privateKey));
        }
        return invokeSign(publickKey).equals(invokeSign(privateKey));
    }

    public String getPublicKey(int code) {
        return randomString(getSign(code), PUBLIC_KEY_LENGTH);
    }

    public String getPublicKey(int code, boolean randomIndex) {
        if (randomIndex) {
            return randomString(code, PUBLIC_KEY_LENGTH);
        }
        return randomString(getSign(code), PUBLIC_KEY_LENGTH);
    }

    public String getPrivateKey(int code) {
        return randomString(getSign(code), PRIVATE_KEY_LENGTH);
    }

    public String getPrivateKey(int code, boolean randomIndex) {
        if (randomIndex) {
            return randomString(code, PRIVATE_KEY_LENGTH);
        }
        return randomString(getSign(code), PRIVATE_KEY_LENGTH);
    }

    /**
     * @Title: getItemIndex
     * @Description: 获取索引
     */
    private int[] getItemIndex(int code, int length) {
        Random ran = new Random(code);
        int[] index = new int[16];
        for (int i = 0; i < index.length;) {
            int temp = ran.nextInt(length);
            if (!ArrayUtils.contains(index, temp)) {
                index[i++] = temp;
            }
        }
        return index;
    }

    /**
     * @Title: invokeSign
     * @Description: 固定位置获取签
     */
    private String invokeSign(String key) {
        int num = key.length() == PRIVATE_KEY_LENGTH ? 64 : 128;
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < 16; i++) {
            sb.append(key.charAt(num * i));
        }
        return sb.toString();
    }

    /**
     * @Title: invokeSign
     * @Description: 随机位置获取签
     */
    private String invokeSign(int code, String key) {
        StringBuilder sb = new StringBuilder();
        int[] index = getItemIndex(code, key.length());
        for (int i = 0; i < index.length; i++) {
            sb.append(key.charAt(index[i]));
        }
        return sb.toString();
    }

    /**
     * @Title: randomString
     * @Description: 公钥秘钥固定位置随机吗
     */
    private String randomString(String sign, int length) {
        int num = length == PRIVATE_KEY_LENGTH ? 0x3f : 0x7f;
        String temp = RandomStringUtils.randomAlphanumeric(length);
        byte[] signBtye = sign.getBytes();
        byte[] bytes = temp.getBytes();
        for (int i = 0, j = 0; i < bytes.length; i++) {
            if ((i & num) == 0) {
                bytes[i] = signBtye[j++];
            }
        }
        return new String(bytes);
    }

    /**
     * @Title: randomString
     * @Description: 公钥秘钥随机位置
     */
    private String randomString(int code, int length) {
        String sign = getSign(code);
        String temp = RandomStringUtils.randomAlphanumeric(length);
        byte[] signBtye = sign.getBytes();
        byte[] bytes = temp.getBytes();
        int[] index = getItemIndex(code, length);
        for (int i = 0; i < index.length; i++) {
            bytes[index[i]] = signBtye[i];
        }
        return new String(bytes);
    }

    public static void main(String[] args) {

        int code = 336786;
        System.out.println("用户对应秘钥随机生成码：" + code + "或者使用手机后6位等");
        System.out.println("**************固定位置**************");
        String sign = GenerateKeyUtils.getDefault().getSign(code);
        System.out.println("获取密签：" + sign);
        String publicKey = GenerateKeyUtils.getDefault().getPublicKey(code);
        System.out.println("获取公钥：" + publicKey);
        System.out.println("公钥长度：" + publicKey.length());
        String privateKey = GenerateKeyUtils.getDefault().getPrivateKey(code);
        System.out.println("获取私钥：" + privateKey);
        System.out.println("私钥长度：" + privateKey.length());

        System.out.println("效验公钥密签："
                + GenerateKeyUtils.getDefault().checkSign(code, publicKey));
        System.out.println("效验私钥密签："
                + GenerateKeyUtils.getDefault().checkSign(code, privateKey));
        System.out
                .println("效验公钥和私钥匹配："
                        + GenerateKeyUtils.getDefault().checkKey(publicKey,
                                privateKey));

        System.out.println("**************随机位置**************");
        System.out.println("获取密签：" + sign);
        publicKey = GenerateKeyUtils.getDefault().getPublicKey(code, true);
        System.out.println("获取公钥：" + publicKey);
        System.out.println("公钥长度：" + publicKey.length());
        privateKey = GenerateKeyUtils.getDefault().getPrivateKey(code, true);
        System.out.println("获取私钥：" + privateKey);
        System.out.println("私钥长度：" + privateKey.length());

        System.out.println("效验公钥密签："
                + GenerateKeyUtils.getDefault()
                        .checkSign(code, publicKey, true));
        System.out.println("效验私钥密签："
                + GenerateKeyUtils.getDefault().checkSign(code, privateKey,
                        true));
        System.out.println("效验公钥和私钥匹配："
                + GenerateKeyUtils.getDefault().checkKey(code, publicKey,
                        privateKey, true));
    }
}
