package Solucion;

import java.io.IOException;
import java.net.Socket;
import java.net.UnknownHostException;

public class ClientMain {
	
		
	private static int puerto = 4030;

	public static void main(String[] args) throws IOException {
		
        // Start ClientThreads
        // Choose desired number of concurrent tasks
        int concurrentTasks = 32;
        System.out.println("Running "+concurrentTasks+" concurrent tasks.");
        ClientThread[] thrs = new ClientThread[concurrentTasks];
        for  (int id=0; id<concurrentTasks; id++) {
            System.out.println("Client "+id+ ": Trying to connect to server. Port: " + puerto);

            // Create a socket to connect to server using the server's port number found in server code
            try{
                Socket socket = new Socket("127.0.0.1",puerto);
                System.out.println("Client "+id+": Connected");
                ClientThread d = new ClientThread(socket,id,0);
                thrs[id] = d;
            }
            catch(UnknownHostException u){
                System.out.println(u);
            }
            catch(IOException i){
                System.out.println(i);
            } 
        }
        for  (int k=0; k<concurrentTasks; k++) {
            thrs[k].start();
        }
	}

}
