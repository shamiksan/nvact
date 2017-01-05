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
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;


/**
 * @author san
 *
 */
public class ImportNessusPlugins {

	private static String mysqluser = "vuser";
    private static String mysqlpw = "vu@ms123";
    private static String mysqldbname = "vactdb";
    private static String mysqldbUrl = "jdbc:mysql://localhost:3310/";
    private static String mysqldbClass = "com.mysql.jdbc.Driver";
    private static String mysqlPluginTable = "test_vact_nessusplugins";

	public static void main(String[] args) {
		final long startTime = System.nanoTime();
	try {
		File fXmlFile = new File("D:\\Eclipsespace\\VACT\\input\\Nessus\\nessus_report_Metasploitable_v1.nessus");
		List<List<String>> lsinsertPlugins = new ArrayList<List<String>>();
		DocumentBuilderFactory dbFactory = DocumentBuilderFactory.newInstance();
		DocumentBuilder dBuilder = dbFactory.newDocumentBuilder();
		Document doc = dBuilder.parse(fXmlFile);
		doc.getDocumentElement().normalize();
		//System.out.println("Root element :" + doc.getDocumentElement().getNodeName());
		NodeList pluginprefList = doc.getElementsByTagName("PluginsPreferences");

		for (int temp = 0; temp < pluginprefList.getLength(); temp++) { 
			Node nNode = pluginprefList.item(temp);
			NodeList itemList = nNode.getChildNodes();//doc.getElementsByTagName("item");
			for (int itemp = 0; itemp < itemList.getLength(); itemp++) {

				Node inNode = itemList.item(itemp);
				//   System.out.println("----------#Child Nodes of Report #-------"+inNode.getNodeName());
			//	
				List <String> lspluginRow = new ArrayList<String>();
				if(inNode.getNodeName().matches("item")){
					NodeList targetsList = inNode.getChildNodes();
					//List <String> lspluginRow = new ArrayList<String>();
					for (int intemp = 0; intemp < targetsList.getLength(); intemp++) {
						Node innerNode = targetsList.item(intemp);
						if (innerNode.getNodeType() == Node.ELEMENT_NODE) {
							Element iiElement = (Element) innerNode;
							lspluginRow.add(iiElement.getTextContent().replaceAll("\\'", "").trim());
						}
					}
					lsinsertPlugins.add(lspluginRow);
				}
			
			}
		}//end for
		
		if(insertDB(mysqlPluginTable,lsinsertPlugins)){
			System.out.println("Data Inserted Successfully.");
		}
	} catch (Exception e) {
		e.printStackTrace();
	}
	final long duration = System.nanoTime() - startTime;
	System.out.println("---Execution Time(sec) ||---"+ duration/1000000000.0+"---|| ");
}//end main
	
	private static boolean insertDB(String strTable, List<List<String>> lsinData) throws SQLException, ClassNotFoundException {
		Connection conn = getMySQLConn();
		//System.out.println("---------Data to be Inserted----Start-------");
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
			 
			String insertQry = "INSERT INTO " + strTable + " (PluginName, PluginID, FullName, PreferenceName, PreferenceType," +
					" PreferenceValues, SelectedValue) VALUES (" + qryData + ")";
			//System.out.println("Insert Query is:"+insertQry);
			ps = conn.prepareStatement(insertQry);
			ps.executeUpdate();
		}
		conn.close();
		//System.out.println("---------Data to be Inserted----End-------");
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
	
	private static String deNuller(String str) {
		return (str == null) ? "" : str;
	}

}
