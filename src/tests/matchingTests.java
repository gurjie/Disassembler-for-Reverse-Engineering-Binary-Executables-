package tests;

import static org.junit.Assert.assertEquals;
import static org.junit.jupiter.api.Assertions.*;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Scanner;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.junit.Before;
import org.junit.jupiter.api.Test;

import capstone.Capstone;
import elf.Elf;

class matchingTests {
	
	private ArrayList<String> registers;
	
	@Before 
	public void setup() {
		registers = new ArrayList<String>();
		this.registers.add(".bp");		
		this.registers.add(".sp");	
		this.registers.add(".ax");		
		this.registers.add(".ah");		
		this.registers.add(".di");		
	}
	
	public int printMatches(String text, String regex) {
	    Pattern pattern = Pattern.compile(regex);
	    Matcher matcher = pattern.matcher(text);
	    // Check all occurrences
	    int p = 0;
	    while (matcher.find()) {
	       // System.out.print("Start index: " + matcher.start());
	       // System.out.print(" End index: " + matcher.end());
	       // System.out.println(" Found: " + matcher.group());
	    	p++;
	    }
		return p;
	}
	
	public int firstIndex(String text, String regex) {
	    Pattern pattern = Pattern.compile(regex);
	    Matcher matcher = pattern.matcher(text);
	    // Check all occurrences
	    while (matcher.find()) {
	    	return matcher.start();
	    }
	    return 0;
	}
	
	@Test // test 1, should be 3 matches for .di
	public void matchTest() {
		String s = "rdi in a rdieo has many rdi in";
		assertEquals("TEST 1: find count rdi in a string", 3,printMatches(s,".di"));
	}
	
	@Test // match w multiple register patterns
	public void matchTest2() {
		setup();
		int occurrences = 0;
		String s = "rdi ineax a ubp tah usp iax ybp";
		for(String x : this.registers) {
			occurrences+=printMatches(s,x);
		}
		assertEquals("TEST 1: find count rdi in a string", 7,occurrences);
	}

	@Test // test 2, should be 3 matches for .di
	public void firstIndexTest() {
		String s = "rdi in a rdieo has many rdi in";
		assertEquals("TEST 1: find rdi first index in a string", 0,firstIndex(s,".di"));
	}
	
	@Test // replace index in string w something else
	public void replaceIndexTest() {
		String s = "rdi in a rdieo has many rdi in";
        StringBuffer buf = new StringBuffer(s);
        int start = firstIndex(s,".di");;
        int end = start+3;
        buf.replace(start, end, "foobar"); 
		assertEquals("TEST 1: find rdi first index in a string", "foobar in a rdieo has many rdi in",buf.toString());
	}
	
	@Test // replace index in string w number
	public void replaceIndexTest2() {
		String s = "rdi in a rdieo has many rdi in";
        StringBuffer buf = new StringBuffer(s);
        int start = firstIndex(s,".di");
        int end = start+3;
        buf.replace(start, end, "1535"); 
		assertEquals("TEST 1: find rdi first index in a string", "1535 in a rdieo has many rdi in",buf.toString());
	}
	
	
	@Test // replace index in string w number
	public void hexMatch() {
		String s = "101209 - 0xa1f4";
		int hexStrlen = 0;
        if(s.contains("0x")) {
        	String[] tmp = s.split("\\s+");
        	for(String st : tmp) {
        		if(st.contains("0x")) {
        			hexStrlen = st.length();
        		}
        	}

        }
        StringBuffer buf = new StringBuffer(s);
        buf.replace(s.indexOf("0x"), s.indexOf("0x")+hexStrlen, "100");
        assertEquals("TEST 1: find rdi first index in a string", "101209 - 100",buf.toString());
	}
	
	@Test 
	public void extractSubStr() {
		String s = "101209 - 0xa1f4";
		int hexStrlen = 0;
        if(s.contains("0x")) {
        	String[] tmp = s.split("\\s+");
        	for(String st : tmp) {
        		if(st.contains("0x")) {
        			hexStrlen = st.length();
        		}
        	}

        }
        String ii = s.substring(s.indexOf("0x"), s.indexOf("0x")+hexStrlen);
        assertEquals("TEST 1: find rdi first index in a string", "0xa1f4",ii);
	}
	
	@Test 
	public void extractSubStrThenReplace() {
		String halfway = "101209 - 0xa1f4";
		int hexStrlen = 0;
        if(halfway.contains("0x")) {
        	String[] tmp = halfway.split("\\s+");
        	for(String st : tmp) {
        		if(st.contains("0x")) {
        			hexStrlen = st.length();
        		}
        	}
        }
        String ii = halfway.substring(halfway.indexOf("0x"), halfway.indexOf("0x")+hexStrlen);
        long x = Long.decode(ii);
        int d = (int) x;
        StringBuffer buf = new StringBuffer(halfway);
        buf.replace(halfway.indexOf("0x"), halfway.indexOf("0x")+hexStrlen, Integer.toString(d));
        
        assertEquals("TEST 1: find rdi first index in a string", "101209 - 41460",buf.toString());
	}
}
