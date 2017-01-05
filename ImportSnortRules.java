/**
 * 
 */
package org.vact;


import java.io.BufferedReader;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.sql.*;


public class ImportSnortRules {
	
	private static String snortrulesdir = "D:\\Eclipsespace\\VACT\\input\\in_snort_rules";
	static Pattern Rule_Parentheses = Pattern.compile("\\((.*?)\\)");
	private static String mysqltableRules = "vact_snort_rules";
	private static String mysqltableRulesRef = "vact_snort_rules_ref";
    
	public static void main(String[] args) {
		// TODO Iterate through directory and list folders
		final long startTime = System.nanoTime();
		listFiles(snortrulesdir);
		final long duration = System.nanoTime() - startTime;
	//	System.out.println("---Execution Time(sec) ||---"+ duration/1000000000.0+"---|| ");
	}
	
	private static void listFiles(String dirpath){
		
		 File snortdir = new File(dirpath);
		 if (snortdir.isDirectory()){
		  for (File flSnortRule : snortdir.listFiles()) {
			  //--System.out.println("\n\n\t###-"+flSnortRule.getName().replaceAll(".rules", "")+"-###\n");
			  String strSnortRuleName = flSnortRule.getName().replaceAll(".rules", "").trim();
			  FileReader frSnortRule = null;
			  BufferedReader brSnortRule = null;
			  Matcher mrule = null;
			  List<HashMap<String, String>> lsSnortRules = null;
			  List<List<String>> lsSnortRuleRefs = null;
			  
			  try {
				frSnortRule = new FileReader(flSnortRule);
				brSnortRule = new BufferedReader(frSnortRule);
				lsSnortRules = new ArrayList<HashMap<String, String>>();
				lsSnortRuleRefs = new ArrayList<List<String>>();
				String strlnSnortRule = brSnortRule.readLine().trim();
				String strSnrtRule [] = null;
				List<String> lstempRuleRef = null;
				List<String> lsRuleRef = null;
				HashMap<String, String> hmVactSnortRules = null;
				StringBuilder strmsg, strref, strclasstype, strsid, strrev = null;
				while(strlnSnortRule != null){
					if(strlnSnortRule.startsWith("alert") || strlnSnortRule.startsWith("# alert")|| strlnSnortRule.startsWith("#alert")){
						hmVactSnortRules = new HashMap<String, String>();
						lstempRuleRef = new ArrayList<String>();
						strmsg = new StringBuilder("");
						strref = new StringBuilder("");
						strclasstype = new StringBuilder("");
						strsid = new StringBuilder("");
						strrev = new StringBuilder("");
						mrule = Rule_Parentheses.matcher(strlnSnortRule);
						
						if(mrule.find()){
							strSnrtRule = strlnSnortRule.substring(strlnSnortRule.indexOf('(') + 1,strlnSnortRule.lastIndexOf(')')).split(";");
							for(int i=0;i<strSnrtRule.length;i++){
								
								if(strSnrtRule[i].trim().startsWith("msg:")){
									strmsg.append(strSnrtRule[i].replaceAll("msg:", "").trim());
								}else if(strSnrtRule[i].trim().startsWith("reference:")){
									strref.append(strSnrtRule[i].replaceAll("reference:", "").trim());
								}else if(strSnrtRule[i].trim().startsWith("classtype:")){
									strclasstype.append(strSnrtRule[i].replaceAll("classtype:", "").trim());
								}else if(strSnrtRule[i].trim().startsWith("sid:")){
									strsid.append(strSnrtRule[i].replaceAll("sid:", "").trim());
								}else if(strSnrtRule[i].trim().startsWith("rev:")){
									strrev.append(strSnrtRule[i].replaceAll("rev:", "").trim());
								}
								//now put into hashmap or arraylist (for handling improper column matching)
								hmVactSnortRules.put("2", strSnortRuleName);
								hmVactSnortRules.put("4", strmsg.toString().replaceAll("'", ""));
								lstempRuleRef.add(strref.toString());
								strref.setLength(0);
								hmVactSnortRules.put("3", strclasstype.toString());
								hmVactSnortRules.put("0", strsid.toString());
								hmVactSnortRules.put("1", strrev.toString());
							}//end for snort rule parse
							
							//add row to lsSnortRules
							lsSnortRules.add(hmVactSnortRules);
							
							//get info from hmVactSnortRules and reference array and add to lsSnortRuleRefs
							for(int i=0; i<lstempRuleRef.size(); i++){
								  lsRuleRef = new ArrayList<String>();
								  if(!lstempRuleRef.get(i).matches("")){
									  String temprule [] = lstempRuleRef.get(i).split(",");
									  lsRuleRef.add(0, hmVactSnortRules.get("0"));
									  lsRuleRef.add(1, hmVactSnortRules.get("1"));
									  lsRuleRef.add(2, temprule[0]);
									  lsRuleRef.add(3, temprule[1].replaceAll("\\\\", "/"));
									  lsSnortRuleRefs.add(lsRuleRef);
								  }
							  }
							
						}
					}
					strlnSnortRule = brSnortRule.readLine();
				}//end while rule ! = null
				brSnortRule.close();
				//insert into DB
				insertDB2(mysqltableRules, lsSnortRules);
				insertDB(mysqltableRulesRef, lsSnortRuleRefs);
				
			  } catch (Exception e) {
				e.printStackTrace();
			  }
			  //insert into db
		   }//end for loop files
		}
	}//end listfiles method
	
	
	private static boolean insertDB(String strTable, List<List<String>> lsinData) throws SQLException, ClassNotFoundException {
		Connection conn = ConnectMySQL.getMySQLConn();
		//System.out.println("---------Data Insertion Snort Rule Refs----Start-------");
		for(List<String> lsOut: lsinData){
			//System.out.println("----Start Row----");
			PreparedStatement ps = null;
			StringBuilder qryData = new StringBuilder();
			for(int i = 0; i< lsOut.size(); i++){
				//System.out.println("data--"+lsOut.get(i)+"--data");
				qryData.append("'"+lsOut.get(i)+"'");
				if(i < lsOut.size()-1){
					qryData.append(",");
				}
			}
			//System.out.println("----End Row----");
			String insertQry = "INSERT INTO " + strTable + " VALUES (" + qryData + ")";
			//System.out.println("Insert Query is:"+insertQry);
			ps = conn.prepareStatement(insertQry);
			ps.executeUpdate();
		}
		conn.close();
		//System.out.println("---------Data Insertion----End-------");
		return true;
	}
	
	private static boolean insertDB2(String strTable, List<HashMap<String,String>> lsinData) throws SQLException, ClassNotFoundException {
		Connection conn = ConnectMySQL.getMySQLConn();
		//System.out.println("---------Data Insertion Snort Rules----Start-------");
		for(HashMap<String, String> hmOut: lsinData){
			//System.out.println("----Start Row----");
			PreparedStatement ps = null;
			StringBuilder qryData = new StringBuilder();
			
			for(String hmkey :hmOut.keySet()){
				qryData.append("'"+hmOut.get(hmkey)+"',");
			}
			qryData.replace(qryData.lastIndexOf(","), qryData.lastIndexOf(",") + 1, "");
			
			//System.out.println("----End Row----");
			 
			String insertQry = "INSERT INTO " + strTable + " (ClassType, ProtoServSoft, Rev, SID, Message) VALUES (" + qryData + ")";
			//System.out.println("Insert Query is:"+insertQry);
			ps = conn.prepareStatement(insertQry);
			ps.executeUpdate();
		}//end hashmap
		conn.close();
		//System.out.println("---------Data Insertion----End-------");
		return true;
	}
	

}
