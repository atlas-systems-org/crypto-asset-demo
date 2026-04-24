import java.security.KeyStore;
import javax.net.ssl.SSLContext;

public class TlsConfig {
    private static final String KEYSTORE_PATH = "/opt/app/keystore.p12";
    private static final String TRUSTSTORE = "classpath:truststore.jks";

    public void init() throws Exception {
        KeyStore.getInstance("PKCS12");
        SSLContext ctx = SSLContext.getInstance("TLS");
    }
}
