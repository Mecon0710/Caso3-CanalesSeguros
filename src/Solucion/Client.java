package Solucion;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.security.PublicKey;
import java.security.SecureRandom;

import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

import java.math.BigInteger;


public class Client {
    private static Socket socket;	
    private static int puerto = 4030;
    private static SecurityFunctions f;

    public static byte[] str2byte( String ss)
	{	
		// Encapsulamiento con hexadecimales
		byte[] ret = new byte[ss.length()/2];
		for (int i = 0 ; i < ret.length ; i++) {
			ret[i] = (byte) Integer.parseInt(ss.substring(i*2,(i+1)*2), 16);
		}
		return ret;
	}

    public static String byte2str( byte[] b )
	{	
		// Encapsulamiento con hexadecimales
		String ret = "";
		for (int i = 0 ; i < b.length ; i++) {
			String g = Integer.toHexString(((char)b[i])&0x00ff);
			ret += (g.length()==1?"0":"") + g;
		}
		return ret;
	}

    private static BigInteger G2X(BigInteger base, BigInteger exponente, BigInteger modulo) {
		return base.modPow(exponente,modulo);
	}

    private static BigInteger calcular_llave_maestra(BigInteger base, BigInteger exponente, BigInteger modulo) {
		return base.modPow(exponente, modulo);
	}

    private static byte[] generateIvBytes() {
	    byte[] iv = new byte[16];
	    new SecureRandom().nextBytes(iv);
	    return iv;
	}
    
    public static void main(String[] args) throws Exception{
        f = new SecurityFunctions();

        // Create a socket to connect to server using the server's port number found in server code
        try{
            socket = new Socket("127.0.0.1",puerto);
            System.out.println("Connected");
        }
        catch(UnknownHostException u){
            System.out.println(u);
        }
        catch(IOException i){
            System.out.println(i);
        } 

        // STEP 1 - Send "SECURE INIT" message to server
        PrintWriter writer = new PrintWriter(socket.getOutputStream(), true);
        writer.println("SECURE INIT");

        // STEP 2 - Server generates G, P and computes G2X
       
        // STEP 3 - Receive G, P, G2X and Sign from server
        BufferedReader reader = new BufferedReader(new InputStreamReader(socket.getInputStream()));
        // Receive G
        String g = reader.readLine();
        System.out.println("G: " + g);
        // Receive P
        String p = reader.readLine();
        System.out.println("p: " + p);
        String g2 = reader.readLine();
        // Receive G2X
        System.out.println("G2X: " + g2);
        String sign = reader.readLine();
        // Receive Sign
        System.out.println("Sig: " + sign);
        byte[] signature = str2byte(sign);

        // STEP 4 & 5 - Verify Signature and send result to server, close connection if ERROR
        PublicKey publicaServidor = f.read_kplus("datos_asim_srv.pub","server key: ");
        String msj = g+","+p+","+g2;
        try {
            boolean result = f.checkSignature(publicaServidor,signature,msj);
            if (result == true){
                System.out.println("OK");
                writer.println("OK");
            }
            else{
                System.out.println("ERROR");
                writer.println("ERROR");
                socket.close();
            }
        } catch (Exception e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }

        // STEP 6 - Compute G2Y and send to server
        SecureRandom r = new SecureRandom();
		int y = Math.abs(r.nextInt());
    	Long longy = Long.valueOf(y);
    	BigInteger biy = BigInteger.valueOf(longy);
        BigInteger g_big = new BigInteger(g);
        BigInteger p_big = new BigInteger(p);
    	BigInteger valor_comun = G2X(g_big,biy,p_big);
    	String str_valor_comun = valor_comun.toString();
    	System.out.println("G2Y: "+str_valor_comun);
        writer.println(str_valor_comun);

        // STEP 7
        // Compute (G^x)^y mod N
        BigInteger g2_big = new BigInteger(g2);
    	BigInteger llave_maestra = calcular_llave_maestra(g2_big,biy,p_big);

        // Derive symmetric keys
    	String str_llave = llave_maestra.toString();
		SecretKey sk_srv = f.csk1(str_llave);
		SecretKey sk_mac = f.csk2(str_llave);
			
		// Generate iv1
        byte[] iv1 = generateIvBytes();
	    String str_iv1 = byte2str(iv1);
		IvParameterSpec ivSpec1 = new IvParameterSpec(iv1);

        // Create request (some integer)
        String request = "1";
        byte[] byt_request = request.getBytes();
        String str_request = new String(byt_request, StandardCharsets.UTF_8);

        // Encrypt request with sk_srv
        byte[] rta_consulta = f.senc(byt_request, sk_srv, ivSpec1, "Client");

        // HMAC using sk_mac and request
	    byte [] rta_mac = f.hmac(byt_request, sk_mac);

        // STEP 8 - Send results
        writer.println(byte2str(rta_consulta));
        writer.println(byte2str(rta_mac));
        writer.println(str_iv1);

        // STEP 9 - Server verifies HMAC

        // STEP 10 - Receive verification result from server
        String server_Response = reader.readLine();
        System.out.println("server response: " + server_Response);

        // STEP 11 - Receive encrypted response, HMAC and iv2
        String server_encry = reader.readLine();
        String server_hmac = reader.readLine();
        String server_iv2 = reader.readLine();

        // Convert to bytes
        byte[] byte_server_encry = str2byte(server_encry);
		byte[] byte_server_hmac = str2byte(server_hmac);
		byte[] byte_server_iv2 = str2byte(server_iv2);
		
        // STEP 12 - Verify HMAC
		IvParameterSpec ivSpec2 = new IvParameterSpec(byte_server_iv2);
	    byte[] descifrado = f.sdec(byte_server_encry, sk_srv,ivSpec2);
	    boolean verificar = f.checkInt(descifrado, sk_mac, byte_server_hmac);
		System.out.println("Integrity check: " + verificar);

        // STEP 13 - Send verification result to server, close connection if ERROR
        if (verificar == true) {
            writer.println("OK");
        }
        else {
            writer.println("ERROR");
            socket.close();
        }
    }
    
}