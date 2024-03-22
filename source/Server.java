import com.google.gson.*;

import java.io.*;
import java.security.*;
import java.util.*;
import java.util.Base64;

import javax.crypto.*;
import javax.net.*;
import javax.net.ssl.*;

import java.net.Socket;
import java.sql.*;
import java.lang.ClassNotFoundException;

import spark.*;

import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import java.nio.ByteBuffer;

import security.src.Security;
import security.src.CheckCommand;
import security.src.UnprotectCommand;
import security.src.ProtectCommand;

public class Server {

    private static Properties config = loadConfig();

    private static String jdbcUrl = config.getProperty("jdbcUrl");
    private static String username = config.getProperty("dbUsername");
    private static String password = config.getProperty("dbPassword");

    // create a hashset to store the accounts that are already connected
    private static HashMap<String, String> connectedAccounts = new HashMap<String, String>();
    private static HashMap<String, String> tasksQueue = new HashMap<String, String>();
    private static ArrayList<Integer> sequenceNumbers = new ArrayList<Integer>();

    public static void startServer(int port) throws IOException {

        ServerSocketFactory factory = SSLServerSocketFactory.getDefault();
        
        ExecutorService executorService = Executors.newFixedThreadPool(10); // Max number of clients

        try (SSLServerSocket listener = (SSLServerSocket) factory.createServerSocket(port)) {
            listener.setNeedClientAuth(true);
            listener.setEnabledCipherSuites(new String[]{"TLS_AES_128_GCM_SHA256"});
            listener.setEnabledProtocols(new String[]{"TLSv1.3"});
            System.out.println("Listening for messages...");

            while (true) {
                try {
                    Socket socket = listener.accept();

                    // Delegate the handling of the client to a new thread
                    executorService.submit(() -> {
                        try {
                            handleClient(socket, Thread.currentThread().getName());
                        } catch (IOException e) {
                            e.printStackTrace();
                        }
                    });
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        } catch (IOException e) {
            e.printStackTrace();
        } finally {
            // Shut down the thread pool when the server is done
            executorService.shutdown();
        }
    }

    private static String processMessage(String message, byte[] signatureBytes, String currentThread) {
        // get first word of message
        String[] message_split = message.split(" ");
        String command = message_split[0];

        try {
            if (command.equals("connecting")) {
                String accountHolderConnection = message_split[2];
                return connection(accountHolderConnection, currentThread);
            }

            if (command.equals("confirm")) {
                 if (!Security.verifySignature(message, signatureBytes, Security.loadPublicKey("keys/" + connectedAccounts.get(currentThread) + "_ser.pub"))) {
                    return "SIGNATURE NOT VALID";
                }
                System.out.println("debug: signature verified successfully");

                // remove confirm from message
                message = message.substring(8);
                String account = connectedAccounts.get(currentThread);

                // iterate over tasksQueue to check if there is a task for this account
                for (Map.Entry<String, String> entry : tasksQueue.entrySet()) {
                    // if message is equal to the task, remove it from the queue where account is equal to the current account
                    if (entry.getValue().equals(message) && entry.getKey().equals(account)) {
                        tasksQueue.remove(entry.getKey());
                        return "confirm processed by server sucessfully";
                    }
                }

                return "no payment in queue to confirm processed by server";
            }

            if (command.equals("addAccountHolder")) {
                if (!Security.verifySignature(message, signatureBytes, Security.loadPublicKey("keys/" + connectedAccounts.get(currentThread) + "_ser.pub"))) {
                    return "SIGNATURE NOT VALID";
                }
                System.out.println("debug: signature verified successfully");

                String accountHolder = message_split[1];
                return addAccountHolder(accountHolder, currentThread);
            } else if (command.equals("checkBalance")) {
                if (!Security.verifySignature(message, signatureBytes, Security.loadPublicKey("keys/" + connectedAccounts.get(currentThread) + "_ser.pub"))) {
                    return "SIGNATURE NOT VALID";
                }
                System.out.println("debug: signature verified successfully");

                return listMovements_checkBalance("cb", currentThread);
            } else if (command.equals("payment")) {
                if (!Security.verifySignature(message, signatureBytes, Security.loadPublicKey("keys/" + connectedAccounts.get(currentThread) + "_ser.pub"))) {
                    return "SIGNATURE NOT VALID";
                }
                System.out.println("debug: signature verified successfully");
                
                String jsonPaymentString = message_split[1];
                return payment(jsonPaymentString, currentThread);
            } else if (command.equals("listMovements")) {
                if (!Security.verifySignature(message, signatureBytes, Security.loadPublicKey("keys/" + connectedAccounts.get(currentThread) + "_ser.pub"))) {
                    return "SIGNATURE NOT VALID";
                }
                System.out.println("debug: signature verified successfully");

                return listMovements_checkBalance("lm", currentThread);
            } else {
                return "Unknown command";
            }
        }
        catch (Exception e){
            e.printStackTrace();
            return "EXCEPTION";
        }

    }

    public static String connection(String accountHolderConnection, String currentThread) {
        
        if (accountExists(accountHolderConnection)) {
            connectedAccounts.put(currentThread, accountHolderConnection);
            return "connection (login) processed by server sucessfully";
        } else {
            JsonObject createAccountJson = new JsonObject();
            JsonObject accountHolderObject = new JsonObject();
            JsonArray accountHolderArray = new JsonArray();

            accountHolderArray.add(accountHolderConnection);
            accountHolderObject.add("accountHolder", accountHolderArray);
            createAccountJson.add("account", accountHolderObject);
            accountHolderObject.addProperty("balance", 1000.0); // initial balance for all new accounts
            accountHolderObject.addProperty("currency", "EUR");

            JsonArray movementsArray = new JsonArray();
            accountHolderObject.add("movements", movementsArray);

            try {
                Class.forName("org.postgresql.Driver");
                Connection connection = DriverManager.getConnection(jdbcUrl, username, password);
    
                String query = "INSERT INTO bank_database (data) VALUES (?::jsonb)";
                PreparedStatement preparedStatement =  connection.prepareStatement(query);
                preparedStatement.setString(1, new Gson().toJson(createAccountJson));
                preparedStatement.executeUpdate();

            } catch (Exception e) {
                e.printStackTrace();
            }

            connectedAccounts.put(currentThread, accountHolderConnection);
        
            return "connection (create new account) processed by server sucessfully";
        }
        
    }

    public static String addAccountHolder(String accountHolder, String currentThread) {
        
        String currentAccountHolder = connectedAccounts.get(currentThread);
        
        try {
            
            byte[] decodeAccountHolder = Base64.getDecoder().decode(accountHolder);

            String accountHolderToAdd = new String(Security.hybridDecrypt(decodeAccountHolder, Security.loadPrivateKey("keys/" + currentAccountHolder + "_ser.key")));
            
            // update database to add new account holder
            try {
                Class.forName("org.postgresql.Driver");
                Connection connection = DriverManager.getConnection(jdbcUrl, username, password);

                // Execute a query to update the account by adding the new account holder
                String query = "UPDATE bank_database\n" +
                        "SET data = jsonb_set(\n" +
                        "    data,\n" +
                        "    '{account,accountHolder}',\n" +
                        "    COALESCE(data->'account'->'accountHolder', '[]'::jsonb) || '[\"" + accountHolderToAdd + "\"]'::jsonb\n" +
                        ")\n" +
                        "WHERE data->'account'->'accountHolder' @> ?::jsonb;\n";

                PreparedStatement preparedStatement = connection.prepareStatement(query);
                preparedStatement.setString(1, "[\"" + currentAccountHolder + "\"]");
                preparedStatement.executeUpdate();

                // Generate and save keys for new account holder
                KeyPair keyPair = Security.generateKeyPair();
                Security.savePublicKey(keyPair.getPublic(), "keys/" + accountHolderToAdd + "_ser.pub");
                Security.savePrivateKey(keyPair.getPrivate(), "keys/" + accountHolderToAdd + "_ser.key");
                System.out.println("debug: keys for new account holder created successfully");

                return "New account holder added to the existing account successfully.";
            } catch (Exception e) {
                e.printStackTrace();
                return "Failed to add account holder. Database error.";
            }        
        } catch (Exception e) {
            e.printStackTrace();
            return "Failed to add account holder. Decryption error.";
        }
    }

    public static String listMovements_checkBalance(String option, String currentThread) {

        try {
            Class.forName("org.postgresql.Driver");
            Connection connection = DriverManager.getConnection(jdbcUrl, username, password);

            String query = "SELECT data FROM bank_database WHERE data->'account'->'accountHolder' @> ?::jsonb";

            PreparedStatement preparedStatement = connection.prepareStatement(query);
            
            // Get account logged in this thread
            String account = connectedAccounts.get(currentThread);

            // Set the parameter value for the account holder
            preparedStatement.setString(1, "[\"" + account + "\"]");
            // Execute the query and retrieve the result set
            ResultSet resultSet = preparedStatement.executeQuery();
            if (resultSet.next()) {

                // Retrieve all data from the database
                JsonObject balanceJson = JsonParser.parseString(resultSet.getString("data")).getAsJsonObject();

                String outputFile = "database/" + account + "_protected.json";
                
                JsonObject balanceJsonProtected = ProtectCommand.protectDocument(balanceJson, outputFile, "keys/" + account + "_ser.pub");
                String balanceJsonString = balanceJsonProtected.toString();

                return balanceJsonString;
            } else {
                System.out.println("No data found for account holder: " + account);
            }
        } catch (Exception e) {
            e.printStackTrace();
        }

        if(option.equals("ln")) {
            return "Unsuccessful list movements";
        }
        
        return "Unsuccessful check balance";
    }

    public static String payment(String jsonPaymentString, String currentThread) {

        try {

            // Get account logged in this thread
            String account = connectedAccounts.get(currentThread);
            // ArrayList to store all account holders
            ArrayList<String> accountHolders = new ArrayList<String>();

            // Search in database what is the accountHolderArray saved for this account
            try {
                Class.forName("org.postgresql.Driver");
                Connection connection = DriverManager.getConnection(jdbcUrl, username, password);

                String query = "SELECT data->'account'->'accountHolder' AS accountHolder FROM bank_database WHERE data->'account'->'accountHolder' @> ?::jsonb";

                PreparedStatement preparedStatement = connection.prepareStatement(query);
                // Set the parameter value for the account holder
                preparedStatement.setString(1, "[\"" + account + "\"]");
                // Execute the query and retrieve the result set
                ResultSet resultSet = preparedStatement.executeQuery();
                if (resultSet.next()) {
                    // Retrieve the accountHolderArray as a JSON array
                    JsonArray accountHolderArray = JsonParser.parseString(resultSet.getString("accountHolder")).getAsJsonArray();

                    // Convert the JSON array to a string
                    String accountHolderString = accountHolderArray.toString();

                    // Convert the string to an arraylist
                    accountHolders = new Gson().fromJson(accountHolderString, ArrayList.class);
                } else {
                    System.out.println("No data found for account holder: " + account);
                }
            } catch (Exception e) {
                e.printStackTrace();
            }

            // Convert the jsonPaymentString to a JsonObject
            JsonObject jsonPayment = JsonParser.parseString(jsonPaymentString).getAsJsonObject();

            // retrieve the sequence number from the jsonPayment
            Integer sequenceNumber = jsonPayment.get("sequenceNumber").getAsInt();
            
            if (sequenceNumbers.contains(sequenceNumber)) {
                return "Invalid payment due to duplicated order";
            }
            
            sequenceNumbers.add(sequenceNumber);

            boolean validJsonPayment = CheckCommand.checkDocument(jsonPayment);
            
            if (!validJsonPayment) {
                return "Invalid payment due to error on CheckCommand";
            }

            // Retrieve the destinationAccountHolder from the jsonPayment
            JsonObject unprotectedJsonPayment = UnprotectCommand.unprotectDocument(jsonPayment, "database/paymentUnprotected.json", "keys/" + account + "_ser.key");

            String destinationAccountHolder = unprotectedJsonPayment.get("destinationAccountHolder").getAsString();
            Double value = unprotectedJsonPayment.get("value").getAsDouble();
            String description = unprotectedJsonPayment.get("description").getAsString();
            String date = unprotectedJsonPayment.get("date").getAsString();       
            
            // if exists a space after description, remove it
            if (description.charAt(description.length() - 1) == ' ') {
                description = description.substring(0, description.length() - 1);
            }

            // check if destinationAccountHolder exists and is not inside the accountHolders array
            for (String accountHolder : accountHolders) {
                if (accountHolder.equals(destinationAccountHolder)) {
                    return "The destinationAccount is equal to the senderAccount";
                }
            }

            //remove the current account from the accountHolders array
            accountHolders.remove(account);

            // create HashMap to store all tasks to be executed for each accountHolder
            for (String accountHolder : accountHolders) {
                // put into accountHolders the accountHolder and the message with payment
                String task = "payment " + destinationAccountHolder + " " + value + " " + description;
                tasksQueue.put(accountHolder, task);
            }
            
            // while taskQueue is not empty, wait 
            while (!tasksQueue.isEmpty()) {
                try {
                    Thread.sleep(1);
                } catch (InterruptedException e) {
                    e.printStackTrace();
                }
            }
            
                        
            if (accountExists(destinationAccountHolder) && !account.equals(destinationAccountHolder)) {
                Double verifiedBalance = verifyBalanceDouble(currentThread);

                if (verifiedBalance < value) {
                    return "Insufficient funds to make payment";
                } else {
                    Double valueToEnter = value * -1;
                    insertPaymentDatabase(account, valueToEnter, description);
                    updateBalance(account, valueToEnter);
                    insertPaymentDatabase(destinationAccountHolder, value, description);
                    updateBalance(destinationAccountHolder, value);
                    
                    return "payment processed by server sucessfully";
                } 

            } else {
                String error = "The destinationAccount is equal to the senderAccount or no data found for destination account holder: " + destinationAccountHolder;
                return error;
            }

        } catch (Exception e) {
            e.printStackTrace();
        }

        return "Unsuccessful payment";
    }

    

    private static boolean accountExists(String accountHolder) {
        try {
            Class.forName("org.postgresql.Driver");
            Connection connection = DriverManager.getConnection(jdbcUrl, username, password);

            String query = "SELECT EXISTS (SELECT id FROM bank_database WHERE data->'account'->'accountHolder' @> ?::jsonb) AS account_exists";
            
            PreparedStatement preparedStatement = connection.prepareStatement(query);
            // Set the parameter value for the account holder
            preparedStatement.setString(1, "[\"" + accountHolder + "\"]");         
            ResultSet resultSet = preparedStatement.executeQuery();
            if (resultSet.next()) {
                // Access the result using resultSet.getBoolean("account_exists")
                boolean accountExists = resultSet.getBoolean("account_exists");
                return accountExists;
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        
        return false;
    }

    public static void deleteDatabase(){
        try {
            Class.forName("org.postgresql.Driver");
            Connection connection = DriverManager.getConnection(jdbcUrl, username, password);

            String query = "DELETE FROM bank_database";
            
            PreparedStatement preparedStatement = connection.prepareStatement(query);
            preparedStatement.executeUpdate();

        } catch (Exception e) {
            e.printStackTrace();
        }

        // delete all files from keys folder except README
        File folder = new File("keys");
        File[] listOfFiles = folder.listFiles();
        for (File file : listOfFiles) {
            if (file.isFile() && !file.getName().equals("README.md")) {
                file.delete();
            }
        }

        // delete all files from database folder except README
        folder = new File("database");
        listOfFiles = folder.listFiles();
        for (File file : listOfFiles) {
            if (file.isFile() && !file.getName().equals("README.md")) {
                file.delete();
            }
        }
    }

    public static void populateDatabase(){
        try {
            Class.forName("org.postgresql.Driver");
            Connection connection = DriverManager.getConnection(jdbcUrl, username, password);

            String query = "INSERT INTO bank_database (data) VALUES\n" + //
                    "('{\n" + //
                    "  \"account\": {\n" + //
                    "    \"accountHolder\": [\"Alice\"],\n" + //
                    "    \"balance\": 872.22,\n" + //
                    "    \"currency\": \"EUR\",\n" + //
                    "    \"movements\": [\n" + //
                    "      {\n" + //
                    "        \"date\": \"09/11/2023\",\n" + //
                    "        \"value\": 1000.00,\n" + //
                    "        \"description\": \"Salary\"\n" + //
                    "      },\n" + //
                    "      {\n" + //
                    "        \"date\": \"15/11/2023\",\n" + //
                    "        \"value\": -77.78,\n" + //
                    "        \"description\": \"Electricity bill\"\n" + //
                    "      },\n" + //
                    "      {\n" + //
                    "        \"date\": \"22/11/2023\",\n" + //
                    "        \"value\": -50.00,\n" + //
                    "        \"description\": \"ATM Withdrawal\"\n" + //
                    "      }\n" + //
                    "    ]\n" + //
                    "  }\n" + //
                    "}');\n" + //
                    "";

            String query2 = "INSERT INTO bank_database (data) VALUES\n" + //
                    "('{\n" + //
                    "  \"account\": {\n" + //
                    "    \"accountHolder\": [\"Bob\"],\n" + //
                    "    \"balance\": 1350.75,\n" + //
                    "    \"currency\": \"EUR\",\n" + //
                    "    \"movements\": [\n" + //
                    "      {\n" + //
                    "        \"date\": \"05/12/2023\",\n" + //
                    "        \"value\": 500.50,\n" + //
                    "        \"description\": \"Bonus\"\n" + //
                    "      },\n" + //
                    "      {\n" + //
                    "        \"date\": \"12/12/2023\",\n" + //
                    "        \"value\": -100.25,\n" + //
                    "        \"description\": \"Grocery shopping\"\n" + //
                    "      },\n" + //
                    "      {\n" + //
                    "        \"date\": \"20/12/2023\",\n" + //
                    "        \"value\": -75.00,\n" + //
                    "        \"description\": \"Dinner with friends\"\n" + //
                    "      }\n" + //
                    "    ]\n" + //
                    "  }\n" + //
                    "}');\n" + //
                    "";

            String query3= "INSERT INTO bank_database (data) VALUES\n" + //
                     "('{\n" + //
                    "  \"account\": {\n" + //
                    "    \"accountHolders\": [\"Eve\", \"Charlie\"],\n" + //
                    "    \"balance\": 1200.75,\n" + //
                    "    \"currency\": \"EUR\",\n" + //
                    "    \"movements\": [\n" + //
                    "      {\n" + //
                    "        \"date\": \"10/11/2023\",\n" + //
                    "        \"value\": 1500.25,\n" + //
                    "        \"description\": \"Initial deposit\"\n" + //
                    "      },\n" + //
                    "      {\n" + //
                    "        \"date\": \"18/11/2023\",\n" + //
                    "        \"value\": -60.45,\n" + //
                    "        \"description\": \"Trip to Italy\"\n" + //
                    "      },\n" + //
                    "      {\n" + //
                    "        \"date\": \"26/11/2023\",\n" + //
                    "        \"value\": -25.50,\n" + //
                    "        \"description\": \"Coffee shop\"\n" + //
                    "      }\n" + //
                    "    ]\n" + //
                    "   }\n" + //
                    "}');\n" + //
                    "";
              
            
            PreparedStatement preparedStatement = connection.prepareStatement(query);
            PreparedStatement preparedStatement2 = connection.prepareStatement(query2);
            PreparedStatement preparedStatement3 = connection.prepareStatement(query3);
            preparedStatement.executeUpdate();
            preparedStatement2.executeUpdate();
            preparedStatement3.executeUpdate();

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static void insertPaymentDatabase(String accountHolder, Double value, String description) {
        try {
            Class.forName("org.postgresql.Driver");
            Connection connection = DriverManager.getConnection(jdbcUrl, username, password);
            
            String date = java.time.LocalDate.now().toString();
            // Convert this format 2023-12-11 to this 09/11/2023
            date = date.substring(8, 10) + "/" + date.substring(5, 7) + "/" + date.substring(0, 4);
            
            // Execute a query to insert the Json object into the database where the accountholder is equal to the string account
            String query = "UPDATE bank_database\n" +
                "SET data = jsonb_set(\n" +
                "    data,\n" +
                "    '{account,movements}',\n" +
                "    COALESCE(data->'account'->'movements', '[]'::jsonb) || '[{\"date\":\"" + date + "\", \"value\": \"" + value + "\", \"description\": \"" + description + "\"}]'::jsonb\n" +
                ")\n" +
                "WHERE data->'account'->'accountHolder' @> ?::jsonb;\n";

            PreparedStatement preparedStatement = connection.prepareStatement(query);
            preparedStatement.setString(1, "[\"" + accountHolder + "\"]"); 
            preparedStatement.executeUpdate();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static void updateBalance(String accountHolder, Double value) {
        try {
            Class.forName("org.postgresql.Driver");
            Connection connection = DriverManager.getConnection(jdbcUrl, username, password);
            // Execute a query to update the balance of accountHolder by adding value to the current balance
            String query = "UPDATE bank_database\n" +
                "SET data = jsonb_set(\n" +
                "    data,\n" +
                "    '{account,balance}',\n" +
                "    to_jsonb((data->'account'->>'balance')::numeric + " + value + ")\n" +
                ")\n" +
                "WHERE data->'account'->'accountHolder' @> ?::jsonb;\n";            

            PreparedStatement preparedStatement = connection.prepareStatement(query);
            preparedStatement.setString(1, "[\"" + accountHolder + "\"]"); 
            preparedStatement.executeUpdate();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static Double verifyBalanceDouble(String currentThread) {

        try {
            Class.forName("org.postgresql.Driver");
            Connection connection = DriverManager.getConnection(jdbcUrl, username, password);

            String query = "SELECT data->'account'->>'balance' AS balance FROM bank_database WHERE data->'account'->'accountHolder' @> ?::jsonb";

            PreparedStatement preparedStatement = connection.prepareStatement(query);
            
            // Get account logged in this thread
            String account = connectedAccounts.get(currentThread);

            // Set the parameter value for the account holder
            preparedStatement.setString(1, "[\"" + account + "\"]");
            // Execute the query and retrieve the result set
            ResultSet resultSet = preparedStatement.executeQuery();
            if (resultSet.next()) {
                // Retrieving the balance from the result set
                String balanceString = resultSet.getString("balance");
                Double balanceDouble = Double.parseDouble(balanceString);

                return balanceDouble;
            } else {
                return 0.0; // the payment will not be processed because will fail condition
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return 0.0;
    }

    private static void handleClient(Socket socket, String currentThread) throws IOException {
        String message = "";
        InputStream is = new BufferedInputStream(socket.getInputStream());
        OutputStream os = new BufferedOutputStream(socket.getOutputStream());

        /* START */

        byte[] messageLengthBytes = new byte[4];
        is.read(messageLengthBytes);
        int messageLength = ByteBuffer.wrap(messageLengthBytes).getInt();

        byte[] messageBytes = new byte[messageLength];
        is.read(messageBytes);

        byte[] signatureLengthBytes = new byte[4];
        is.read(signatureLengthBytes);
        int signatureLength = ByteBuffer.wrap(signatureLengthBytes).getInt();

        byte[] signatureBytes = new byte[signatureLength];
        is.read(signatureBytes);

        message = new String(messageBytes, 0, messageLength);        

        // Get first word of message
        String[] message_split = message.split(" ");
        String tempAccountHolder = message_split[0];
        // Get the remaining message
        String publicKeyStringClient = message.substring(tempAccountHolder.length() + 1);

        // Convert the publicKeyBytes to a PublicKey
        try {
            PublicKey publicKeyClient = Security.getPublicKeyfromString(publicKeyStringClient);
            // Save public key to a file
            Security.savePublicKey(publicKeyClient, "keys/" + tempAccountHolder + "_ser.pub");
        } catch (Exception e) {
            e.printStackTrace();
        }
        
        // Generate a new key pair
        KeyPair keyPair = Security.generateKeyPair();

        // The private key is equal from the client and the server
        PublicKey publicKey = keyPair.getPublic();
        PrivateKey privateKey = keyPair.getPrivate();

        // Save the private key to a file
        Security.savePrivateKey(privateKey, "keys/" + tempAccountHolder + "_ser.key");

        // Send to the client the public key of the server
        String publicKeyString = Base64.getEncoder().encodeToString(publicKey.getEncoded());
        
        os.write(publicKeyString.getBytes());
        os.flush();

        /* END */

        while (true) {
            try {

                messageLengthBytes = new byte[4];
                is.read(messageLengthBytes);
                messageLength = ByteBuffer.wrap(messageLengthBytes).getInt();

                messageBytes = new byte[messageLength];
                is.read(messageBytes);

                signatureLengthBytes = new byte[4];
                is.read(signatureLengthBytes);
                signatureLength = ByteBuffer.wrap(signatureLengthBytes).getInt();

                signatureBytes = new byte[signatureLength];
                is.read(signatureBytes);

                message = new String(messageBytes, 0, messageLength);
                System.out.printf("Server received %d bytes: %s - (%s)%n", messageLength, message, currentThread);

                if (message.equals("exit")){
                    os.write("exit command received, closing connection".getBytes());
                    os.flush();
                    break;
                }

                String response = processMessage(message, signatureBytes, currentThread);
                os.write(response.getBytes());
                os.flush();
            }
            catch (Exception e){
                e.printStackTrace();
            }

            is = new BufferedInputStream(socket.getInputStream());
            os = new BufferedOutputStream(socket.getOutputStream());
        }

        try {
            is.close();
            os.close();
            socket.close();
        } catch (IOException i) {
            System.out.println(i);
        }
    }

    private static Properties loadConfig() {
        Properties properties = new Properties();
        try (FileInputStream input = new FileInputStream("credentials/configServer.properties")) {
            properties.load(input);
        } catch (IOException e) {
            e.printStackTrace();
        }
        return properties;
    }

    public static void main(String args[]) throws IOException {
        // clean database and keys folder before running the server
        deleteDatabase();

        System.setProperty("javax.net.ssl.keyStore", config.getProperty("keyStorePath"));
        System.setProperty("javax.net.ssl.keyStorePassword", config.getProperty("keyStorePassword"));
        System.setProperty("javax.net.ssl.trustStore", config.getProperty("trustStorePath"));
        System.setProperty("javax.net.ssl.trustStorePassword", config.getProperty("trustStorePassword"));
        populateDatabase(); // populate database with some demo accounts

        createKeys.main(args); // create keys for all accounts
        startServer(5000);
    }
}