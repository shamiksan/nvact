/**
 * 
 */
package org.vact;

import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.DocumentBuilder;
import org.w3c.dom.Document;
import org.w3c.dom.NodeList;
import org.w3c.dom.Node;
import org.w3c.dom.Element;
import java.io.File;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.sql.*;


public class ImportVuln {

	/**
	 * @param args
	 */
	static Pattern PORT_Round = Pattern.compile("\\((.*?)\\)");
	static Pattern DATA_Pattern = Pattern.compile("Synopsis :|Description :|Solution :|Risk factor :|CVSS Base Score :|Plugin output :|CVE :|BID :|Other references :");
	static Pattern CVSSDATA_Pattern = Pattern.compile("AV:|/AC:|/Au:|/C:|/I:|/A:");
	private static String mysqluser = "vuser";
    private static String mysqlpw = "vu@ms123";
    private static String mysqldbname = "vactdb";
    private static String mysqldbUrl = "jdbc:mysql://localhost:3310/";
    private static String mysqldbClass = "com.mysql.jdbc.Driver";
    private static String mysqlVulndbTable = "vulndb";
    private static String mysqlVulndbrefTable = "vulndbref";
    private static String mysqlVulndbCVSSTable = "vulndbcvss";
    private static String testmysqlVactTable = "testvulndb";
    private static String nessusReportWinXPSP2 = "nessus_report_01.nessus";
    private static String nessusReportWinXPSP1 = "nessus_report_WinXPSP1_v1.nessus";
    private static String nessusReportMetasploitable = "nessus_report_Metasploitable_v1.nessus";
    private static String nessusReportKioptrix = "nessus_report_Kioptrix_v1.nessus";

	public static void main(String[] args) {
		final long startTime = System.nanoTime();
		try {
			File fXmlFile = new File("D:\\Eclipsespace\\VACT\\input\\Nessus\\" + nessusReportKioptrix); //change the input file as applicable
			HashMap<String, String> hmHostDetails = new HashMap<String, String>();
			List<List<String>> lsinsertData = new ArrayList<List<String>>();
			
			DocumentBuilderFactory dbFactory = DocumentBuilderFactory.newInstance();
			DocumentBuilder dBuilder = dbFactory.newDocumentBuilder();
			Document doc = dBuilder.parse(fXmlFile);
			doc.getDocumentElement().normalize();
			NodeList reportList = doc.getElementsByTagName("Report");

			for (int temp = 0; temp < reportList.getLength(); temp++) { 
				Node nNode = reportList.item(temp);
				NodeList targetList = nNode.getChildNodes();//doc.getElementsByTagName("Targets");
				for (int itemp = 0; itemp < targetList.getLength(); itemp++) {
					Node inNode = targetList.item(itemp);
					if(inNode.getNodeName().matches("Targets")){
						NodeList targetsList = inNode.getChildNodes();
						for (int intemp = 0; intemp < targetsList.getLength(); intemp++) {
							Node innerNode = targetsList.item(intemp);
							if (innerNode.getNodeType() == Node.ELEMENT_NODE) {
								Element iiElement = (Element) innerNode;
								hmHostDetails.put("TargetIPAdddr", getTagValue("value", iiElement));
							}
						}
					}//end if Targets
				}//end for Targets
			}//end for reportList

			//parse ReportHost
			NodeList reporthostList = doc.getElementsByTagName("ReportHost");
			
			for (int temp = 0; temp < reporthostList.getLength(); temp++) {//as of now only one iteration
				Node nNode = reporthostList.item(temp);
				if (nNode.getNodeType() == Node.ELEMENT_NODE) {
					Element eElement = (Element) nNode;
			
					hmHostDetails.put("HostName", getTagValue("HostName", eElement).trim());
					hmHostDetails.put("StartTime", getTagValue("startTime", eElement).trim());
					hmHostDetails.put("StopTime", getTagValue("stopTime", eElement).trim());
					hmHostDetails.put("OSName", getTagValue("os_name", eElement).trim());
					hmHostDetails.put("MACAddr", getTagValue("mac_addr", eElement).trim());
					// one level down
					NodeList innerList = doc.getElementsByTagName("ReportItem");
					//--System.out.println("----------###-------------");

					for (int intemp = 0; intemp < innerList.getLength(); intemp++) { //main report loop
						HashMap<String, String> hmVulnDB = new HashMap<String, String>();
						Node innerNode = innerList.item(intemp);
						if (innerNode.getNodeType() == Node.ELEMENT_NODE) {
							Element iElement = (Element) innerNode;

							//processing
							List <String> servproto =  procPortElement(getTagValue("port", iElement));//it contains servproto,portno,protocol
							
							hmVulnDB.put("PortNo", servproto.get(1));
							hmVulnDB.put("Protocol", servproto.get(2));
							hmVulnDB.put("ServProto", servproto.get(0));
							hmVulnDB.put("Severity", getTagValue("severity", iElement).trim());
							hmVulnDB.put("PluginID", getTagValue("pluginID", iElement).trim());
							if(!"0".equalsIgnoreCase(hmVulnDB.get("PluginID"))){
								hmVulnDB.put("PluginName", deNuller(getTagValue("pluginName", iElement)));
							} else{
								hmVulnDB.put("PluginName", "");
							}
							HashMap<String, String> nessusData = new HashMap<String, String>();
							if("PORT".equalsIgnoreCase(getTagValue("data", iElement).trim())){
								hmVulnDB.put("Synopsis", "PORT");
							} else {//normal scan data not port scan info
								hmVulnDB.put("Synopsis", "");
								nessusData = procDataElement(getTagValue("data", iElement));//need hashmap because of ill-formed values
							}
							
							//replace and trim \ from risk factor
							List <String> lstRow = new ArrayList<String>();
							lstRow.add(0, hmHostDetails.get("TargetIPAdddr")); //TargetIP
							lstRow.add(1, hmHostDetails.get("HostName")); //HostName
							lstRow.add(2, hmHostDetails.get("StartTime")); //StartTime
							lstRow.add(3, hmHostDetails.get("StopTime")); //StopTime
							lstRow.add(4, hmHostDetails.get("OSName")); //OSName
							lstRow.add(5, hmHostDetails.get("MACAddr")); //MACaddr
							lstRow.add(6, hmVulnDB.get("PortNo")); //PortNo
							lstRow.add(7, hmVulnDB.get("Protocol")); //Protocol
							lstRow.add(8, hmVulnDB.get("ServProto")); //Servproto
							lstRow.add(9, hmVulnDB.get("Severity")); //SeverityNessus
							lstRow.add(10, hmVulnDB.get("PluginID")); //NessPluginId
							lstRow.add(11, hmVulnDB.get("PluginName").replaceAll("\\'", "").trim()); //NessPluginName
							if("PORT".equalsIgnoreCase(hmVulnDB.get("Synopsis"))){
								lstRow.add(12, ""); //VulnSynopsis
								lstRow.add(13, ""); //VulnDesc
								lstRow.add(14, ""); //VulnSoln
								lstRow.add(15, ""); //VulnRiskfactor
								lstRow.add(16, ""); //VulnCVSSBaseScore
								lstRow.add(17, ""); //NessPluginOutp
								lstRow.add(18, ""); //VulnCVE
								lstRow.add(19, ""); //VulnBID
								lstRow.add(20, ""); //VulnOtherRef
							} else{
								lstRow.add(12, deNuller(nessusData.get("Synopsis :")).replaceAll("\\'", "").trim()); //VulnSynopsis //changed later on
								lstRow.add(13, deNuller(nessusData.get("Description :")).replaceAll("\\'", "").trim()); //VulnDesc
								lstRow.add(14, deNuller(nessusData.get("Solution :")).replaceAll("\\'", "").trim()); //VulnSoln
								lstRow.add(15, deNuller(nessusData.get("Risk factor :").replaceAll("\\/", "").trim())); //VulnRiskfactor
								lstRow.add(16, deNuller(nessusData.get("CVSS Base Score :")).trim()); //VulnCVSSBaseScore
								lstRow.add(17, deNuller(nessusData.get("Plugin output :")).replaceAll("\\'", "").replaceAll(" {5,}", "").trim()); //NessPluginOutp
								lstRow.add(18, deNuller(nessusData.get("CVE :")).trim()); //VulnCVE
								lstRow.add(19, deNuller(nessusData.get("BID :")).trim()); //VulnBID //to do this later
								lstRow.add(20, deNuller(nessusData.get("Other references :")).trim()); //VulnOtherRef
							}
							//insert into arraylist of arrays for insertion into DB
							lsinsertData.add(lstRow);
						}// end if inner element
					}//end for main report loop
				} //end if
			} //end for ReportHost
			
			//insert into DB
			if(insertDB(mysqlVulndbTable,lsinsertData)){//for testing hostvact only(addition of BID
				System.out.println("Data Inserted Successfully.");
				if(insertVulnRef(mysqlVulndbTable,mysqlVulndbrefTable)){
					System.out.println("VulnRef data inserted successfully.");
					if(insertVulnCVSS(mysqlVulndbTable,mysqlVulndbCVSSTable)){
						System.out.println("VulnCVSS data inserted successfully.");
					}
				}
			}
			
		} catch (Exception e) {
			e.printStackTrace();
		}
		final long duration = System.nanoTime() - startTime;
		System.out.println("---Execution Time(sec) ||---"+ duration/1000000000.0+"---|| ");
	}//end main
	
	
	private static boolean insertVulnRef(String strTabVactdb, String strTabVactrefdb) throws SQLException, ClassNotFoundException {
		
		List<HashMap<String, String>> lsVulndbData = new ArrayList<HashMap<String, String>>();
		HashMap<String, String> hmVulndbRow = null;
		Connection conn = getMySQLConn();
		String selectQry = "select TargetIP, HostName, PortNo, Protocol, Servproto, NessPluginId, VulnCVE, VulnBID, VulnOtherRef from " + strTabVactdb;
		Statement st = conn.createStatement ();
		st.executeQuery (selectQry);
		ResultSet rs = st.getResultSet ();
		
		   while (rs.next ())
		   {
			  hmVulndbRow = new HashMap<String, String>();
		      hmVulndbRow.put("TargetIP",rs.getString("TargetIP"));
		      hmVulndbRow.put("HostName",rs.getString("HostName"));
		      hmVulndbRow.put("PortNo",rs.getString("PortNo"));
		      hmVulndbRow.put("Protocol",rs.getString("Protocol"));
		      hmVulndbRow.put("Servproto",rs.getString("Servproto"));
		      hmVulndbRow.put("NessPluginId",rs.getString("NessPluginId"));
		      hmVulndbRow.put("VulnCVE",rs.getString("VulnCVE"));
		      hmVulndbRow.put("VulnBID",rs.getString("VulnBID"));
		      hmVulndbRow.put("VulnOtherRef",rs.getString("VulnOtherRef"));
		      lsVulndbData.add(hmVulndbRow);
		   }
		   rs.close ();
		   st.close ();
		
		//split the ref data and fill list to be inserted
		   List<HashMap<String, String>> lsVulndbrefinData = new ArrayList<HashMap<String, String>>(); 
		   
		   HashMap<String, String> hmVulndbrefCVERow = null;
		   String strrefTargetIP,strrefHostName,strrefPortNo,strrefProtocol,strrefServproto,strrefNessPluginId = null;
		
		   for(HashMap<String, String> hmOut: lsVulndbData){
				   strrefTargetIP = hmOut.get("TargetIP");
				   strrefHostName = hmOut.get("HostName");
				   strrefPortNo = hmOut.get("PortNo");
				   strrefProtocol = hmOut.get("Protocol");
				   strrefServproto = hmOut.get("Servproto");
				   strrefNessPluginId = hmOut.get("NessPluginId");
				   
				   String strVulnCVE = hmOut.get("VulnCVE");
				   if(!strVulnCVE.trim().equals("") && strVulnCVE.contains("CVE-")){
					   String tempCVE [] = strVulnCVE.split(",");
					   for(int i=0; i<tempCVE.length; i++){
						   hmVulndbrefCVERow = new HashMap<String, String>();
						   hmVulndbrefCVERow.put("VulnRefType", "CVE");
						   hmVulndbrefCVERow.put("VulnRefDetails", tempCVE[i].replace("CVE-", ""));
						   hmVulndbrefCVERow.put("TargetIP", strrefTargetIP);
						   hmVulndbrefCVERow.put("HostName", strrefHostName);
						   hmVulndbrefCVERow.put("PortNo", strrefPortNo);
						   hmVulndbrefCVERow.put("Protocol", strrefProtocol);
						   hmVulndbrefCVERow.put("Servproto", strrefServproto);
						   hmVulndbrefCVERow.put("NessPluginId", strrefNessPluginId);
						   lsVulndbrefinData.add(hmVulndbrefCVERow);
					   }
				   }
				  
				   String strVulnBID = hmOut.get("VulnBID");
				   if(!strVulnBID.trim().equals("")){
					   String tempBID [] = strVulnBID.split(",");
					   for(int i=0; i<tempBID.length; i++){
					       hmVulndbrefCVERow = new HashMap<String, String>();
						   hmVulndbrefCVERow.put("VulnRefType", "BID");
						   hmVulndbrefCVERow.put("VulnRefDetails", tempBID[i]);
						   hmVulndbrefCVERow.put("TargetIP", strrefTargetIP);
						   hmVulndbrefCVERow.put("HostName", strrefHostName);
						   hmVulndbrefCVERow.put("PortNo", strrefPortNo);
						   hmVulndbrefCVERow.put("Protocol", strrefProtocol);
						   hmVulndbrefCVERow.put("Servproto", strrefServproto);
						   hmVulndbrefCVERow.put("NessPluginId", strrefNessPluginId);
						   lsVulndbrefinData.add(hmVulndbrefCVERow);
					   }
				   }
				   
				   
				   String strVulnOtherRef = hmOut.get("VulnOtherRef");
				   if(!strVulnOtherRef.trim().equals("")){
					   String tempOtherRef [] = strVulnOtherRef.split(",");
					   for(int i=0; i<tempOtherRef.length; i++){
					       hmVulndbrefCVERow = new HashMap<String, String>();
					       String arrtempOtherRef [] = tempOtherRef[i].split(":");
						   hmVulndbrefCVERow.put("VulnRefType", arrtempOtherRef[0]);
						   hmVulndbrefCVERow.put("VulnRefDetails", arrtempOtherRef[1]);
						   hmVulndbrefCVERow.put("TargetIP", strrefTargetIP);
						   hmVulndbrefCVERow.put("HostName", strrefHostName);
						   hmVulndbrefCVERow.put("PortNo", strrefPortNo);
						   hmVulndbrefCVERow.put("Protocol", strrefProtocol);
						   hmVulndbrefCVERow.put("Servproto", strrefServproto);
						   hmVulndbrefCVERow.put("NessPluginId", strrefNessPluginId);
						   lsVulndbrefinData.add(hmVulndbrefCVERow);
					   }
				   }
				}  //end for loop over list
			
		//insert into db
		System.out.println("---------Reference Data to be Inserted----Start-------");
		for(HashMap<String, String> hmOut: lsVulndbrefinData){
			//System.out.println("----Start Row----");
			PreparedStatement ps = null;
			StringBuilder qryData = new StringBuilder();
			
			for(String hmkey :hmOut.keySet()){
				qryData.append("'"+hmOut.get(hmkey)+"',");
			}
			qryData.replace(qryData.lastIndexOf(","), qryData.lastIndexOf(",") + 1, "");
			
			String insertQry = "INSERT INTO " + strTabVactrefdb + " (VulnRefType, Servproto, NessPluginId, PortNo, TargetIP, VulnRefDetails, Protocol, HostName) VALUES (" + qryData + ")";
			//--System.out.println("Insert Query is:"+insertQry);
			ps = conn.prepareStatement(insertQry);
			ps.executeUpdate();
		}
		conn.close();                                                                                                                                                
		System.out.println("---------Reference Data Inserted----End-------");
		return true;
	}
	
	
	private static boolean insertVulnCVSS(String strTabVactdb, String strTabVactcvssdb) throws SQLException, ClassNotFoundException {
		
		List<HashMap<String, String>> lsVulndbData = new ArrayList<HashMap<String, String>>();
		HashMap<String, String> hmVulndbRow = null;
		Connection conn = getMySQLConn();
		String selectQry = "select TargetIP, HostName, PortNo, Protocol, Servproto, NessPluginId, VulnCVE, VulnCVSSBaseScore, " +
				"VulnBID, VulnOtherRef from " + strTabVactdb + " where VulnCVSSBaseScore != '' ";
		Statement st = conn.createStatement ();
		st.executeQuery (selectQry);
		ResultSet rs = st.getResultSet ();
		
		   while (rs.next ())
		   {
			  hmVulndbRow = new HashMap<String, String>();
		      hmVulndbRow.put("TargetIP",rs.getString("TargetIP"));
		      hmVulndbRow.put("HostName",rs.getString("HostName"));
		      hmVulndbRow.put("PortNo",rs.getString("PortNo"));
		      hmVulndbRow.put("Protocol",rs.getString("Protocol"));
		      hmVulndbRow.put("Servproto",rs.getString("Servproto"));
		      hmVulndbRow.put("NessPluginId",rs.getString("NessPluginId"));
		      hmVulndbRow.put("VulnCVE",rs.getString("VulnCVE"));
		      hmVulndbRow.put("VulnCVSSBaseScore",rs.getString("VulnCVSSBaseScore"));
		      hmVulndbRow.put("VulnBID",rs.getString("VulnBID"));
		      hmVulndbRow.put("VulnOtherRef",rs.getString("VulnOtherRef"));
		      lsVulndbData.add(hmVulndbRow);
		   }
		   rs.close ();
		   st.close ();
		
		//split the CVSS data and fill list to be inserted
		   List<HashMap<String, String>> lsVulndbCVSSinData = new ArrayList<HashMap<String, String>>(); 
		   
		   HashMap<String, String> hmVulndbrefCVERow = null;
		   String strrefTargetIP,strrefHostName,strrefPortNo,strrefProtocol,strrefServproto,strrefNessPluginId,strVulnCVE,
		   strVulnCVSSBaseScoreNo,strVulnCVSS_AV,strVulnCVSS_AC,strVulnCVSS_Au,strVulnCVSS_CI,strVulnCVSS_II,strVulnCVSS_AI,
		   strVulnBID,strVulnOtherRef = null;
		   Matcher cvssrule = null;
		   for(HashMap<String, String> hmOut: lsVulndbData){
				   strrefTargetIP = hmOut.get("TargetIP");
				   strrefHostName = hmOut.get("HostName");
				   strrefPortNo = hmOut.get("PortNo");
				   strrefProtocol = hmOut.get("Protocol");
				   strrefServproto = hmOut.get("Servproto");
				   strrefNessPluginId = hmOut.get("NessPluginId");
				   strVulnCVE = hmOut.get("VulnCVE");
				   strVulnBID = hmOut.get("VulnBID");
				   strVulnOtherRef = hmOut.get("VulnOtherRef");
				   
				   HashMap<String, String> VulnCVSSBSData = new HashMap<String, String>();
				   String strVulnCVSSBaseScore = hmOut.get("VulnCVSSBaseScore");
				   cvssrule = PORT_Round.matcher(strVulnCVSSBaseScore);
					
				   if(!strVulnCVSSBaseScore.trim().equals("") && strVulnCVSSBaseScore.contains("CVSS") && cvssrule.find()){
					
					   strVulnCVSSBaseScoreNo = strVulnCVSSBaseScore.substring(0, strVulnCVSSBaseScore.indexOf('(')).trim();
					   VulnCVSSBSData = splitCVSSData(strVulnCVSSBaseScore.substring(strVulnCVSSBaseScore.indexOf('(') + 1, strVulnCVSSBaseScore.indexOf(')')).replace("CVSS2#", ""));
					   hmVulndbrefCVERow = new HashMap<String, String>();
						   hmVulndbrefCVERow.put("TargetIP", strrefTargetIP);
						   hmVulndbrefCVERow.put("HostName", strrefHostName);
						   hmVulndbrefCVERow.put("PortNo", strrefPortNo);
						   hmVulndbrefCVERow.put("Protocol", strrefProtocol);
						   hmVulndbrefCVERow.put("Servproto", strrefServproto);
						   hmVulndbrefCVERow.put("NessPluginId", strrefNessPluginId);
						   hmVulndbrefCVERow.put("VulnCVE", strVulnCVE);
						   hmVulndbrefCVERow.put("VulnCVSSBaseScoreNo", strVulnCVSSBaseScoreNo);
						   hmVulndbrefCVERow.put("VulnBID", strVulnBID);
						   hmVulndbrefCVERow.put("VulnOtherRef", strVulnOtherRef);
						   hmVulndbrefCVERow.put("CVSS_AV", VulnCVSSBSData.get("AV:"));
						   hmVulndbrefCVERow.put("CVSS_AC", VulnCVSSBSData.get("/AC:"));
						   hmVulndbrefCVERow.put("CVSS_Au", VulnCVSSBSData.get("/Au:"));
						   hmVulndbrefCVERow.put("CVSS_C", VulnCVSSBSData.get("/C:"));
						   hmVulndbrefCVERow.put("CVSS_I", VulnCVSSBSData.get("/I:"));
						   hmVulndbrefCVERow.put("CVSS_A", VulnCVSSBSData.get("/A:"));
						   
						   lsVulndbCVSSinData.add(hmVulndbrefCVERow);
					  // }end tempCVE for loop
				   }
				}  //end for loop over list
			
		//insert into db
		System.out.println("---------CVSS Data to be Inserted----Start-------");
		for(HashMap<String, String> hmOut: lsVulndbCVSSinData){
			//System.out.println("----Start Row----");
			PreparedStatement ps = null;
			StringBuilder qryData = new StringBuilder();
			
			for(String hmkey :hmOut.keySet()){
				qryData.append("'"+hmOut.get(hmkey)+"',");
			}
			qryData.replace(qryData.lastIndexOf(","), qryData.lastIndexOf(",") + 1, "");
			
			String insertQry = "INSERT INTO " + strTabVactcvssdb + " (VulnCVSS_AV, VulnCVSSBaseScore, VulnCVSS_II, Servproto, PortNo," +
					" NessPluginId, VulnCVSS_AI, VulnCVSS_AC, VulnCVSS_CI, HostName, VulnOtherRef, VulnCVE, VulnBID, " +
					" TargetIP, VulnCVSS_Au, Protocol) VALUES (" + qryData + ")";
			
			//System.out.println("Insert Query is:"+insertQry);
			ps = conn.prepareStatement(insertQry);
			ps.executeUpdate();
		}
		conn.close();                                                                                                                                                
		System.out.println("---------CVSS Data Inserted----End-------");
		return true;
	}
	
	
	private static boolean insertDB(String strTable, List<List<String>> lsinData) throws SQLException, ClassNotFoundException {
		Connection conn = getMySQLConn();
		System.out.println("---------Data to be Inserted----Start-------");
		for(List<String> lsOut: lsinData){
			//--System.out.println("----Start Row----");
			PreparedStatement ps = null;
			StringBuilder qryData = new StringBuilder();
			for(int i = 0; i< lsOut.size(); i++){
				//--System.out.println("data--"+lsOut.get(i)+"--data");
				qryData.append("'"+lsOut.get(i)+"'");
				if(i < lsOut.size()-1){
					qryData.append(",");
				}
			}
			//--System.out.println("----End Row----");
			String insertQry = "INSERT INTO " + strTable + " (TargetIP, HostName, StartTime, StopTime, OSName, MACaddr, PortNo," +
					" Protocol, Servproto, SeverityNessus, NessPluginId, NessPluginName, VulnSynopsis, VulnDesc, VulnSoln, VulnRiskfactor," +
					" VulnCVSSBaseScore, NessPluginOutp, VulnCVE, VulnBID, VulnOtherRef) VALUES (" + qryData + ")"; 
			//--
			System.out.println("Insert Query is:"+insertQry);
			ps = conn.prepareStatement(insertQry);
			ps.executeUpdate();
		}
		conn.close();
		System.out.println("---------Data to be Inserted----End-------");
		return true;
	}
	
	
	private static Connection getMySQLConn() throws SQLException, ClassNotFoundException{
		 Class.forName(mysqldbClass);
         Connection conn = DriverManager.getConnection(mysqldbUrl+mysqldbname, mysqluser, mysqlpw);
		return conn;
	}
	
	private static String getTagValue(String sTag, Element eElement) {
		NodeList nList = eElement.getElementsByTagName(sTag).item(0).getChildNodes();
		Node nVal = (Node) nList.item(0);
		return nVal.getNodeValue();
	}

	private static List<String> procPortElement (String port){
		List<String> servproto = new ArrayList<String>();
		//split string into two
		String port1[] = port.trim().split(" ");
		
		Matcher mport1 = PORT_Round.matcher(port);
		if(mport1.find()){
			String portproto[] = port1[1].substring(port1[1].indexOf('(') + 1,port1[1].lastIndexOf(')')).split("\\/");
			servproto.add(0, port1[0]);
			servproto.add(1,portproto[0]);
			servproto.add(2,portproto[1]);
		} else{
			String temportproto[] = port1[0].split("\\/");
			servproto.add(0, temportproto[0]);
			servproto.add(1,"");
			servproto.add(2,temportproto[1]);
		}
		return servproto;
	}

	private static HashMap<String, String> procDataElement (String data){
		List<String> nessData = new ArrayList<String>();  
		HashMap<String, String> hmData = new HashMap<String, String>();
		String dataStr = data.trim().replaceAll("\\\\n", " ");
		return hmData = splitData(dataStr);
	}

	private static HashMap<String, String> splitData(String str) {
		List<String> tkns = splitStr(str, DATA_Pattern);//use precompiled pattern
		HashMap<String, String> hmData = new HashMap<String, String>();
		for(int i=1; i<tkns.size(); i++){//discarding the first 0th element as it's ""
			hmData.put(tkns.get(i), tkns.get(++i));
		}
		return hmData;
	}
	
	private static HashMap<String, String> splitCVSSData(String str) {
		List<String> tkns = splitStr(str, CVSSDATA_Pattern);//use precompiled pattern
		HashMap<String, String> hmData = new HashMap<String, String>();
		
		for(int i=1; i<tkns.size(); i++){//discarding the first 0th element as it's ""
			hmData.put(tkns.get(i), tkns.get(++i));
		}
		return hmData;
	}
	
	

	private static List<String> splitStr(String s, Pattern pattern) {
		assert s != null;
		assert pattern != null;
		Matcher m = pattern.matcher(s);
		List<String> ret = new ArrayList<String>();
		int start = 0;
		while (m.find()) {
			ret.add(s.substring(start, m.start()));
			ret.add(m.group());
			start = m.end();
		}
		ret.add(start >= s.length() ? "" : s.substring(start));
		return ret;
	}
	
	private static String deNuller(String str) {
		return (str == null) ? "" : str;
	}
	
	
}//end of class
