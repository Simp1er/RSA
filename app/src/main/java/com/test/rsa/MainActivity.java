package com.test.rsa;

import androidx.appcompat.app.AppCompatActivity;

import android.os.Bundle;
import android.util.Log;
import android.widget.TextView;

import javax.security.auth.login.LoginException;

public class MainActivity extends AppCompatActivity {

    // Used to load the 'native-lib' library on application startup.
    static {
        System.loadLibrary("native-lib");
    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        // Example of a call to a native method
        TextView tv = findViewById(R.id.sample_text);
        //tv.setText(stringFromJNI());
        String base64PublicKey = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDP0tzYxBF5IGfNvuIHzAqvza/ZxfH8aEiPFA4nY/W3js+cG3JUU86Jkc7jUG9XfGdW6SJ38ANs5tyWqYkJyoUErB2PjQQQDmHhbgpBUSeOdwGr/LPtrTrotrNXwpRY9eodkcbcMlbT0gvdnohRSISCjJ2KmFcBMkeO9R2DWe6oIwIDAQAB";
        String result = native_rsa(base64PublicKey,"I am test");
        // 针对公钥处理的数据，其填充内容为伪随机的16进制字符串，每次操作的填充内容都不一样。
        // aJ/86HjYwa66vl6d4262kRcd6yb8fKUrvupxigEJmkgegWTfP/JIYmlW+mEaa8om+LYeeKOm+WBHHrZWyXQL4xxUXlzi9Wh4qLhq3R22hBwedO8tROAOeu+lx3PHvS9zv6pKO5+Zk/ul5jb+wFYmZAKVjb3GVqc9M87/8mjudA0=
        // MQC24dJ6J874BdsV38XqH7rO1ZTZHymylVYgHBt+fT2Wh7qtylF2oRBaA1ecwFTB7Jf1dIqk6Rdv+1bu3VBewOk3EM6CD/pyojdu40aWTkAn5ELA/2K/Lbnb+0ShRSFs9/FCk7XU/YA0Z9x3Re3xH/QXv0RaEpITx9G4FQ53BeI=
        // uLjStWsA2oyi6Q6c/O8nDJIIggcyRor8yUR8/YyIHPqm6vHZyEuXssebVi/Fi941dUPsHKPK+SZu+GQ3I7NDZL572J+HAVD9haKovdRjheKCC2MwoidqD8kukFtU+3hl83AciD4dCW41YEC1ylQCFcGoRscRJ8Dz7KppUBM/bvg=
        // zfGO4zinmkKSzQRufA7sr956HE5WXrcL94HFBXfYq6tcqMlX+mJ+DFoJljVy66E5wCyq1qa2dFrgC1+ZYUTHqt6LQ+3QS4JG2l7u+HYKc2c9C+AfU+RrF0aGYas37yLJr3Qi4EZTuuZOygI4ZQqJBtBynXBFhMPQmhMksPzg/yE=
        Log.i("RSA-native",result);
        String javaResult = RSAUtils.encrypt(base64PublicKey,"I am test");
        // cbHiZ2utz4/vFcXmoj8OFmKvjbnzXLxgixISrwyOaCsFOhOz2GLYlTpiKGxBKQh3/pUEgBm5WvoO
        //    ow8PQLTPHFtCwNBzqZWcC8yfhN+p7b6twQFk8f5wzy6R1P4s/P39PnXCmf6zlPNF1hW4Qmm8nPKm
        //    kXGFStia7G5HeEt0siU=
        Log.i("RSA-Java",javaResult);

    }

    /**
     * A native method that is implemented by the 'native-lib' native library,
     * which is packaged with this application.
     */
    public native String stringFromJNI();
    public static native final String native_rsa(String base64PublicKey, String content);
}
