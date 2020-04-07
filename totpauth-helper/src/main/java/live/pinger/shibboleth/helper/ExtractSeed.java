package live.pinger.shibboleth.helper;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class ExtractSeed{


	public static void main(String args[]){
		if(args.length != 1){
			System.err.println("Incorrect number of args provided");
		}
		
		else{
			System.out.println("Argument provided: " + args[0]);
			System.out.println("Encrypted Seed:  " + extractSeed(args[0]));
		}
	}

	private static String extractSeed(String input){
		//build a pattern to use for matching the seed
		String pattern = "(.*)totpseed=\\((.*?)\\)(.*)";
		Pattern r = Pattern.compile(pattern);

		//Matcher for the pattern to the input
		Matcher m = r.matcher(input);


		//Find the pattern in the input, and return the second capture group
		// Which based on our pattern, is the totpseed
		if(m.find( )){
			return m.group(2);
		}

		else{
			return "NoSeed";
		}
	}
}
