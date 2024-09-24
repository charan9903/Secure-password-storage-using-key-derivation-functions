import java.security.SecureRandom;
import java.util.*;

public class Bcrypt
{

    public static void main(String[] args) {
	Scanner s=new Scanner(System.in);
	System.out.println("Enter password: ");
        String password = s.nextLine();
	System.out.println("Enter Cost Factor: ");
        int costFactor = s.nextInt(); // You can adjust the cost factor as needed

        String hashedPassword = bcrypt(password, costFactor);
        System.out.println("Hashed password: " + hashedPassword);
    }

    public static String bcrypt(String password, int costFactor) {
        SecureRandom random = new SecureRandom();
        byte[] salt = new byte[16];
        random.nextBytes(salt);

        String hashedPassword = BCrypt.hashpw(password, BCrypt.gensalt(costFactor));
        
        return hashedPassword;
    }

    public static class BCrypt {
        public static String hashpw(String password, String salt) 
	{
            // Implement bcrypt hashing algorithm here
            return password + salt; // This is a placeholder, not a secure hashing implementation
        }

        public static String gensalt(int costFactor) 
	{
            // Generate the salt based on cost factor and return it
            return "$2b$" + costFactor + "$ABCDEFGHIJKLMNOPQRST"; // Placeholder salt
        }
    }
}