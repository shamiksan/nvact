/**
 * 
 */
package org.vact;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;


public class ImportMetasploitModules {
	private static String win_metamodulesdir = "D:\\Eclipsespace\\VACT\\input\\in_meta_modules";
	private static String linux_metamodulesdir = "D:\\Eclipsespace\\VACT\\input\\in_meta_modules_linux";
	static Pattern Rule_Parentheses = Pattern.compile("\\((.*?)\\)");
	private static String mysqltableModules = "vact_meta_mods";
	private static String mysqltableModRefs = "vact_meta_mod_refs";
	private static String mysqltableModTgts = "vact_meta_mod_tgts";

	/**
	 * @param args
	 */
	public static void main(String[] args) {
		// TODO Iterate through directory and list folders
		final long startTime = System.nanoTime();
		listModules(linux_metamodulesdir);
		final long duration = System.nanoTime() - startTime;
		System.out.println("---\\||//---"+ duration+"---\\||//---");
	}
	
	
	private static void listModules(String dirpath){
		
		 File metaDir = new File(dirpath);
		 if (metaDir.isDirectory()){
			 String strFilename = "";
		  for (File flMetaMod : metaDir.listFiles()) {//start for loop root dir
			  strFilename = flMetaMod.getName().trim();
			  //--System.out.println("\n\n\t###-"+strFilename+"-###\n");
			  //declare lists for insertion
			  
			  if(flMetaMod.isDirectory()){//if dir is folder
				  for(File flMetaModRb : flMetaMod.listFiles()){// for inside folder list files
					  //declare lists for each file
					  List<HashMap<String, String>> lsMetaMods = null;
					  List<List<String>> lsMetaModRefs = null;
					  List<List<String>> lsMetaModTargets = null;
					  
					  lsMetaMods = new ArrayList<HashMap<String, String>>();
					  //lsMetaModRefs = new ArrayList<List<String>>();
					  //lsMetaModTargets = new ArrayList<List<String>>();
					  
					  HashMap<String, String> hmMetaModDetails = null;
					  List<String> lsModRef = null;
					  List<String> lstempModRef = null;
					  List<String> lsModTgt = null;
					  List<String> lstempModTgt = null;
						
					  StringBuilder strRank = null, strName = null, strDesc = null, strVersion = null, strPriv = null, strPlatform = null, strDiscDate = null;
					
					  if(flMetaModRb.toString().trim().endsWith(".rb")){ //reading the ruby file
						  String strMetaModRb = flMetaModRb.getName().replaceAll(".rb", "").trim();
						  //--System.out.println("\n\t***-"+strMetaModRb.replaceAll(".rb", "")+"-***");
						  FileReader frMetaModRb = null;
						  BufferedReader brMetaModRb = null;
						  
						  hmMetaModDetails = new HashMap<String, String>();
						  //lsModRef = new ArrayList<String>();
						  //lsModTgt = new ArrayList<String>();
						  lstempModRef = new ArrayList<String>();
						  lstempModTgt = new ArrayList<String>();
						  
						  strRank = new StringBuilder("");
						  strName = new StringBuilder("");
						  strDesc = new StringBuilder("");
						  strVersion = new StringBuilder("");
						  strPriv = new StringBuilder("");
						  strPlatform = new StringBuilder("");
						  strDiscDate = new StringBuilder("");
						  
						  //----------------- Start File Processing --------------------------------
						  try{
							  frMetaModRb = new FileReader(flMetaModRb);
							  brMetaModRb = new BufferedReader(frMetaModRb);
							  String strlnMetaModRb = brMetaModRb.readLine().trim();
							   
							  while(strlnMetaModRb != null){
								  //var declarations
								  
								  if(strlnMetaModRb.trim().startsWith("Rank")){
									  if(strlnMetaModRb.contains("#")){
										  strRank.append(strlnMetaModRb.substring(0, strlnMetaModRb.indexOf("#")).replace("Rank =", "").trim().replace("Ranking", ""));  
									  }else{
										  strRank.append(strlnMetaModRb.replace("Rank =", "").trim().replace("Ranking", ""));
										  //--System.out.println("---Rank---"+strRank+"---");
									  }
								  }else if(strlnMetaModRb.trim().startsWith("'Name'")){
									  strName.append(strlnMetaModRb.replace("'Name'", "").replace("=>", "").replace(",", "").replace("'", "").trim());
									  //--System.out.println("---Name---"+strName+"---");
								  }else if(strlnMetaModRb.trim().startsWith("'Description'")){
									  strDesc = new StringBuilder("");
									  while(!(strlnMetaModRb.trim().endsWith("},"))){
										  strlnMetaModRb = brMetaModRb.readLine();
										  strDesc.append(strlnMetaModRb.replace("\\","").replace("'", "\\'").trim()+" ");//.trim());
									  }
									  //--System.out.println("--Description--"+strDesc+"---");
								  }else if(strlnMetaModRb.trim().startsWith("'Version'")){
									  strVersion.append(strlnMetaModRb.replace("'Version'", "").replace("=>", "").replace("$","").replace("'", "").replace(",", "").trim());
									  //--System.out.println("---Version---"+strVersion+"---");
								  }else if(strlnMetaModRb.trim().startsWith("'References'")){
									  Boolean blStop = false;
									  while(!blStop){
										  strlnMetaModRb = brMetaModRb.readLine(); 
										  if((strlnMetaModRb.trim().startsWith("[")) && (strlnMetaModRb.trim().contains("]"))){
											  //System.out.println("---References---"+strlnMetaModRb+"---");
											  if(strlnMetaModRb.contains("#")){
												  lstempModRef.add(strlnMetaModRb.substring(0, strlnMetaModRb.indexOf("#")).replace("[", "").replace("],", "").trim());  
											  }else{
												  lstempModRef.add(strlnMetaModRb.replace("[", "").replace("],", "").trim());
											  }
										  } else if(strlnMetaModRb.trim().startsWith("],")){
											  blStop = true;
										  }
									  }
								  }else if(strlnMetaModRb.trim().startsWith("'Targets'")){
									  Boolean blStop = false;
									  while(!blStop){
										  strlnMetaModRb = brMetaModRb.readLine(); 
										  if((strlnMetaModRb.trim().startsWith("[")) && (!strlnMetaModRb.replace("[","").trim().matches(""))){
											  //System.out.println("---Targets---"+strlnMetaModRb+"---");
											  lstempModTgt.add(strlnMetaModRb.replace("[", "").replace("],", "").replace("'","").replace(",","").trim());
										  } else if(strlnMetaModRb.trim().startsWith("],")){
											  blStop = true;
										  }
									  }
								  }else if(strlnMetaModRb.trim().startsWith("'Privileged'")){
									  strPriv.append(strlnMetaModRb.replace("'Privileged'", "").replace("=>", "").replace(",", "").trim());
									  //--System.out.println("---Privileged---"+strPriv+"---");
								  }else if(strlnMetaModRb.trim().startsWith("'Platform'")){
									  if(strPlatform.equals("")){
										  strPlatform.append(strlnMetaModRb.replace("'Platform'", "").replace("=>", "").replace("'", "").replace(",", "").trim());
										  //System.out.println("---Platform---"+strPlatform+"---");
									  }else{
										  strPlatform.setLength(0);
										  strPlatform.append(strlnMetaModRb.replace("'Platform'", "").replace("=>", "").replace("'", "").replace(",", "").trim());
									  }
								  }else if(strlnMetaModRb.trim().startsWith("'DisclosureDate'")){
									  if(strlnMetaModRb.contains("#")){
										  strRank.append(strlnMetaModRb.substring(0, strlnMetaModRb.indexOf("#")).replace("'DisclosureDate'", "").replace("=>", "").replace("'", "").replace("))","").replace(",", "").trim());  
									  }else{
										  strDiscDate.append(strlnMetaModRb.replace("'DisclosureDate'", "").replace("=>", "").replace("'", "").replace("))","").replace(",", "").trim());
										  //--System.out.println("---DisclosureDate---"+strDiscDate+"---");
									  }
									  
								  }
								  strlnMetaModRb = brMetaModRb.readLine(); //reads next line **don't trim() else NPE!
							  }//end while
							  brMetaModRb.close();//close buffer reading of file
							  
							  //fill hm and lists
							  hmMetaModDetails.put("0", strName.toString());
							  hmMetaModDetails.put("1", strVersion.toString());
							  hmMetaModDetails.put("2", strFilename);//servsoftproto
							  hmMetaModDetails.put("3", strRank.toString());
							  hmMetaModDetails.put("4", strDesc.toString().replace("},", "").trim());
							  hmMetaModDetails.put("5", strPriv.toString());
							  hmMetaModDetails.put("6", strPlatform.toString());
							  hmMetaModDetails.put("7", strDiscDate.toString());
							  
							  lsMetaModRefs = new ArrayList<List<String>>();
							  for(int i=0; i<lstempModRef.size(); i++){
								  lsModRef = new ArrayList<String>();
								  if(!lstempModRef.get(i).matches("")){
									  String temprule [] = lstempModRef.get(i).split(",");
									  lsModRef.add(0, hmMetaModDetails.get("0"));
									  lsModRef.add(1, hmMetaModDetails.get("1"));
									  lsModRef.add(2, temprule[0].replace("'","").trim());
									  lsModRef.add(3, temprule[1].replace("'","").trim());
									  lsMetaModRefs.add(lsModRef);
								  }
							  }
							  
							  lsMetaModTargets = new ArrayList<List<String>>();
							  for(int i=0; i<lstempModTgt.size(); i++){
								  lsModTgt = new ArrayList<String>();
								  if(!lstempModTgt.get(i).matches("")){
									  lsModTgt.add(0, hmMetaModDetails.get("0"));
									  lsModTgt.add(1, hmMetaModDetails.get("1"));
									  lsModTgt.add(2, lstempModTgt.get(i));
									  lsMetaModTargets.add(lsModTgt);
								  }
							  }
							  
							 //insert into db 
							 insertDB2(mysqltableModules, hmMetaModDetails); 
							 insertDB(mysqltableModRefs, lsMetaModRefs);
							 insertDB(mysqltableModTgts, lsMetaModTargets);
							  
						  }catch(Exception e){
							  e.printStackTrace();
						  }
						  //----------------- End File Processing --------------------------------
					  }//end if ruby file
				  }//end inside folder list files
			  }//end if dir is folder
		   }//end for loop root dir
		}//end if
	}//end listfiles method
	
	
	private static boolean insertDB(String strTable, List<List<String>> lsinData) throws SQLException, ClassNotFoundException {
		Connection conn = ConnectMySQL.getMySQLConn();
		//--System.out.println("---------Data Insertion MetaMod Refs/Tgts ----Start-------");
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
			//--System.out.println("Insert Query is:"+insertQry);
			ps = conn.prepareStatement(insertQry);
			ps.executeUpdate();
		}
		conn.close();
		//System.out.println("---------Data Insertion----End-------");
		return true;
	}
	
	private static boolean insertDB2(String strTable, HashMap<String,String> hminData) throws SQLException, ClassNotFoundException {
		Connection conn = ConnectMySQL.getMySQLConn();
		//--System.out.println("---------Data Insertion Meta Mods----Start-------");
		
			//System.out.println("----Start Row----");
			PreparedStatement ps = null;
			StringBuilder qryData = new StringBuilder();
			
			for(String hmkey :hminData.keySet()){
				qryData.append("'"+hminData.get(hmkey)+"',");
			}
				qryData.replace(qryData.lastIndexOf(","), qryData.lastIndexOf(",") + 1, "");
			
				//System.out.println("----End Row----");
			 
				String insertQry = "INSERT INTO " + strTable + " (Rank, ServSoftProto, Version, ModName, DisclosureDate, Platform, Privileged, Description) VALUES (" + qryData + ")";
				//--System.out.println("Insert Query is:"+insertQry);
				ps = conn.prepareStatement(insertQry);
				ps.executeUpdate();
			
		conn.close();
		//--System.out.println("---------Data Insertion----End-------");
		return true;
	}

}//end class
