package Solucion;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;
import java.security.PublicKey;
import java.security.SecureRandom;

import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

import java.math.BigInteger;


public class ClientThread extends Thread{

    // constantes
	
	// Atributos
    private Socket socket;
	private int id;
	private String dlg;	
	private SecurityFunctions f;	
	private int mod;

	ClientThread (Socket csP, int idP, int modP) {
		this.socket = csP;
		dlg = new String("concurrent client " + idP + ": ");
		id = idP;
		/*
		 *  Concurrent clients run in one of three modes: 
		 *  0-4 concurrent tasks 
		 *  1-16 concurrent tasks 
		 *  2-32 concurrent tasks 
		 */
		mod = modP;
	}

    public void run() {
		
	    System.out.println(dlg + "starting.");
	    f = new SecurityFunctions();

        try {

            PrintWriter writer = new PrintWriter(socket.getOutputStream() , true);
            BufferedReader reader = new BufferedReader(new InputStreamReader(socket.getInputStream()));
                            
            // STEP 1 - Send "SECURE INIT" message to server
            writer.println("SECURE INIT");

            // STEP 2 - Server generates G, P and computes G2X

            // STEP 3 - Receive G, P, G2X and Sign from server
            // Receive G
            String g = reader.readLine();
            System.out.println(dlg+"G: " + g);
            // Receive P
            String p = reader.readLine();
            System.out.println(dlg+"P: " + p);
            // Receive G2X
            String g2x = reader.readLine();
            System.out.println(dlg+"G2X: " + g2x);
            // Receive Sign
            String sign = reader.readLine();
            System.out.println(dlg+"Sign: " + sign);
            byte[] signature = str2byte(sign);
                
            // STEP 4 & 5 - Verify Signature and send result to server, close connection if ERROR

            //long start = System.nanoTime();
            //long end = System.nanoTime();      
            //System.out.println("Client --- Elapsed Time for SYM encryption in nano seconds: "+ (end-start)); 

            PublicKey publicaServidor = f.read_kplus("datos_asim_srv.pub",dlg);
            String msj = g+","+p+","+g2x;
            try {
                long start1 = System.nanoTime();
                boolean result = f.checkSignature(publicaServidor,signature,msj);
                long end1 = System.nanoTime();
                System.out.println(dlg+" --- Elapsed Time for Signature verification in nano seconds: "+ (end1-start1));
                if (result == true){
                    System.out.println(dlg+"Verify signature: OK");
                    writer.println("OK");
                }
                else{
                    System.out.println(dlg+"Verify signature: ERROR");
                    System.out.println(dlg+"Closing connection");
                    writer.println("ERROR");
                    socket.close();
                }
            } catch (Exception e) {
                e.printStackTrace();
            }

            // STEP 6 - Compute G2Y and send to server
            long start2 = System.nanoTime();
            SecureRandom r = new SecureRandom();
            int y = Math.abs(r.nextInt());
            Long longy = Long.valueOf(y);
            BigInteger biy = BigInteger.valueOf(longy);
            BigInteger g_big = new BigInteger(g);
            BigInteger p_big = new BigInteger(p);
            BigInteger valor_comun = G2Y(g_big,biy,p_big);
            long end2 = System.nanoTime();
            String str_valor_comun = valor_comun.toString();
            System.out.println(dlg+"G2Y: "+str_valor_comun);
            writer.println(str_valor_comun);
            System.out.println(dlg+" --- Elapsed Time for G2Y computation in nano seconds: "+ (end2-start2));

            // STEP 7
            // Compute (G^x)^y mod N (llave maestra)
            BigInteger g2_big = new BigInteger(g2x);
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

            // Encrypt request with sk_srv
            byte[] rta_consulta = f.senc(byt_request, sk_srv, ivSpec1, dlg);

            // HMAC using sk_mac and request
            long start3 = System.nanoTime();
            byte [] rta_mac = f.hmac(byt_request, sk_mac);
            long end3 = System.nanoTime();
            System.out.println(dlg+" --- Elapsed Time for HMAC generation in nano seconds: "+ (end3-start3));

            // STEP 8 - Send results
            writer.println(byte2str(rta_consulta));
            writer.println(byte2str(rta_mac));
            writer.println(str_iv1);

            // STEP 9 - Server verifies HMAC

            // STEP 10 - Receive verification result from server
            String server_Response = reader.readLine();
            System.out.println(dlg+"Server HMAC verification result: " + server_Response);

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

            // STEP 13 - Send verification result to server, close connection if ERROR
            if (verificar == true) {
                System.out.println(dlg+"Integrity check: OK");
                writer.println("OK");
            }
            else {
                System.out.println(dlg+"Integrity check: ERROR");
                System.out.println(dlg+"Closing connection");
                writer.println("ERROR");
                socket.close();
            }
            
        } catch (Exception e) { e.printStackTrace(); }
	}


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

    private static BigInteger G2Y(BigInteger base, BigInteger exponente, BigInteger modulo) {
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

}
