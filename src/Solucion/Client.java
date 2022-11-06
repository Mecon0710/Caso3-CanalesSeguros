package Solucion;

import java.io.BufferedReader;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;
import java.net.UnknownHostException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.Random;
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
    
    public static void main(String[] args) throws IOException{
        f = new SecurityFunctions();
        //creates a socket to connect to server using the server's port number found in server code
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

        //Make a printwriter and write the message to the socket
        PrintWriter writer = new PrintWriter(socket.getOutputStream());
        writer.println("SECURE INIT"); // <- println
        writer.flush();                // <- flush
       
        //reader to read the response from the server
        BufferedReader reader = new BufferedReader(new InputStreamReader(socket.getInputStream()));

        //Reade server response 4 times to get p,g,g2x, sign
         
        String g = reader.readLine();
        System.out.println("G: " + g);
        String p = reader.readLine();
        System.out.println("p: " + p);
        String g2 = reader.readLine();
        System.out.println("G2X: " + g2);
        String sign = reader.readLine();
        System.out.println("Sig: " + sign);
        byte[] signature = str2byte(sign);
        System.out.println("Sig Bytes: " + signature);
        //reader.close();

        PublicKey publicaServidor = f.read_kplus("datos_asim_srv.pub","server key: ");
        System.out.println(publicaServidor);

        String msj = g+","+p+","+g2;

        try {
            boolean result = f.checkSignature(publicaServidor,signature,msj);
            if (result == true){
                System.out.println("OK");
                writer.println("OK"); // <- println
                writer.flush();                // <- flush
            }else{
                System.out.println("ERROR");
                writer.println("ERROR"); // <- println
                writer.flush();                // <- flush
            }
        } catch (Exception e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        //Diffie-Hellman Algorithm
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
        writer.flush();
    }
    
}
