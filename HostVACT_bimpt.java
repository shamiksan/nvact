
package org.vact;

import org.w3c.dom.Document;
import org.w3c.dom.NodeList;
import org.w3c.dom.Node;
import org.w3c.dom.Element;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.ResultSetMetaData;
import java.sql.SQLException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class HostVACT_bimpt {

	private static String mysqluser = "vuser";
    private static String mysqlpw = "vu@ms123";
    private static String mysqldbname = "vactdb";
    private static String mysqldbUrl = "jdbc:mysql://localhost:3310/";
    private static String mysqldbClass = "com.mysql.jdbc.Driver";
    private static String hvactOutputDir = "D:\\Eclipsespace\\VACT\\output\\InputSharpe\\";
    private static String hvactSharpeFilename = "hvactSharpe";
    private static String hostIP1 = "192.168.210.129";
    private static String hostIP2 = "192.168.33.128";
    private static String hostIP3 = "192.168.56.134";
    private static String hostIP4 = "192.168.56.132";
    
	public static void main(String[] args) {
		final long startTime = System.nanoTime();
		 	Connection conn = null;
	        PreparedStatement pst = null;
	        ResultSet rs = null;

		// TODO Run query for host vact , load data structures with query data
		String strHostVACTqry = " select distinct(d.ReferenceDetails) as dCVE, a.RefDetails as aCVE, r.VulnRefDetails as vCVE from " +
				" vulndbref r inner join vulndb v on r.NessPluginId = v.NessPluginId " +
				" left join vact_meta_mod_refs a on r.VulnRefDetails = a.RefDetails " +
				" left join vact_snort_rules_ref d on r.VulnRefDetails = d.ReferenceDetails " +
				" where r.VulnRefType = 'CVE' " +
				" and v.vulnsoln not in ( '' ,  'n/a') " +
				" and v.TargetIP = '" + hostIP1 + "' "+
				" and r.VulnRefDetails in (select r.vulnrefdetails " +
					"   from vulndbref  r inner join vulndb v " +
					"	on r.NessPluginId = v.NessPluginId " +
					"	where r.VulnRefType = 'CVE' " +
					"	and v.VulnRiskfactor not in('None', '') " +
					"    ) ";
		
		try {
			conn = getMySQLConn();
			pst = conn.prepareStatement(strHostVACTqry);
			rs = pst.executeQuery();
			ResultSetMetaData mtD = rs.getMetaData();
			
			
			ArrayList<String> columns = new ArrayList<String>();
			ArrayList<String[]> results= new ArrayList<String[]>(); 
			int numberOfColumns = mtD.getColumnCount();
			//System.out.println("The no. of columns is: "+ numberOfColumns);
			for(int i = 1; i<= numberOfColumns; i++){
			    columns.add(mtD.getColumnName(i));
		//	    System.out.print(" "+mtD.getColumnName(i).toString()+" ");
			}
			//System.out.println("-----------------------------------------------------");
			while (rs.next()){
			    String[] row = new String[numberOfColumns];
			    for (int i = 0; i < numberOfColumns; i++){
			    	row[i] = (String) rs.getObject(i+1);
			    }
			    results.add(row);
			}
		//	System.out.println("\n");
			for(String[] resrow: results){
				for(int j = 0; j< resrow.length; j++){
		//			System.out.print("\t"+ deNuller(resrow[j])+"  ");
				}
		//		System.out.println("");
			}
			
			
		HostVACT_bimpt hvi = new HostVACT_bimpt();
		hvi.createHVACTSharpeInput(columns, results);	
			
		} catch (SQLException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (ClassNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		// TODO Run logic, create output into SHARPE initially take simple values for prob. later input CVSS values from 
		final long duration = System.nanoTime() - startTime;
		System.out.println("---Execution Time(sec) ||---"+ duration/1000000000.0+"---|| ");	
	}//end main
	
	private void createHVACTSharpeInput( ArrayList<String> columns, ArrayList<String[]> results) {
		final String faulttreekw =   "ftree";
		final String faulttreevactkw =   "hvact";
		final String nodeprekw =   "basic";
		final String repeatnodeprekw =   "repeat";
		final String nodeprobkw =   "prob";
		final String andkw =   "and";
		final String orkw =   "or";
		final String notkw =   "not";
		final String bindkw =   "bind";
		final String endkw =   "end";
		final String expressionkw =   "expr";
		final String sysprobkw =   "sysprob";
		final String commonprobkw =   "p";
		final String vulnprobkw =   "pv";
		final String attprobkw =   "pa";
		final String detprobkw =   "pd";
		final String mitprobkw =   "pm";
		final String commonprobval =   ".5";
		final String zeroprobval =   "0";
		final String vulnnodekw =   "v";
		final String attnodekw =   "a";
		final String detnodekw =   "d";
		final String mitnnodekw =   "m";
		final String andvakw =   "va";
		final String anddmkw =   "dm";
		final String notanddmkw =   "ndm";
		final String andvadmkw =   "vadm";
		final String ortopkw =   "o";
		final String loopkw =   "loop";
		final String hvactprobkw =   "phvact";
		final String varkw =   "var";
		final String bimptkw =   "bimpt";
		final String bimpttimeval =   "2";
		final String bimpttimevar =   "q";
				
		BufferedWriter writer;
		// output to file
		try {
			Date sysdate = new Date();
			SimpleDateFormat ft = new SimpleDateFormat ("dd-MM-yyyy-hh-mm-ss");
			String strdate = ft.format(sysdate);
			writer = new BufferedWriter(new OutputStreamWriter(
			          new FileOutputStream(hvactOutputDir+hvactSharpeFilename+"_"+"hvact_bimpt_"+strdate.toString()+".flt"), "utf-8"));
			     
			writer.newLine();
			writer.write("format 8 ");
			writer.newLine();
			writer.write("factor on");
			writer.newLine();
			writer.newLine();
			
			//the columns are in order dCVE, aCVE, vCVE
			writer.write(faulttreekw+" "+faulttreevactkw+"1"); //start with naming the fault tree for host vact in top line -- ftree hvact1
			writer.newLine();
			for (int i = 0; i < results.size(); i++) {
				String vulnnode = null;
				String attnode = null;
				String detnode = null;
				String mitnode = null;
				String commonprob = null;
				String[] resrow = results.get(i);
				for(int j = 0; j< resrow.length; j++){
					//System.out.print("\t"+ deNuller(resrow[j])+"  ");
					if (j==0){detnode = deNuller(resrow[j]);
						}else if (j==1){attnode = deNuller(resrow[j]);
						}else if (j==2){vulnnode = deNuller(resrow[j]);
										mitnode = vulnnode;
						}
				}
				writer.write("* VACT Quartet: -- "+vulnnode+" -- "+attnode+" -- "+detnode+" -- "+mitnode+" -- ");
				writer.newLine();
				commonprob = getProbVal(commonprobkw, vulnnode);
				//write to the file code for each vact quartet 
				writer.write(nodeprekw+" "+vulnnodekw+(i+1)+" "+nodeprobkw+"("+((vulnnode == "") ? "p" : commonprob)+")"); //basic v1 prob(p)
				//writer.write(nodeprekw+" "+vulnnodekw+(i+1)+" "+nodeprobkw+"("+((vulnnode == "") ? "p" : vulnprobkw)+")"); //basic v1 prob(pv)
				writer.newLine();
				writer.write(nodeprekw+" "+attnodekw+(i+1)+" "+nodeprobkw+"("+((attnode == "") ? "p" : commonprob)+")"); //basic a1 prob(p)
				//writer.write(nodeprekw+" "+attnodekw+(i+1)+" "+nodeprobkw+"("+attprobkw+")"); //basic a1 prob(pa)
				writer.newLine();
				writer.write(nodeprekw+" "+detnodekw+(i+1)+" "+nodeprobkw+"(1)"); //repeat d1 prob(0) {hardcoded detection}
				//writer.write(repeatnodeprekw+" "+detnodekw+(i+1)+" "+nodeprobkw+"("+((detnode == "") ? "0" : commonprobkw)+")"); //repeat d1 prob(p)
				//writer.write(nodeprekw+" "+detnodekw+(i+1)+" "+nodeprobkw+"("+((detnode == "") ? "p" : commonprob)+")"); //basic d1 prob(p)
				//writer.write(nodeprekw+" "+detnodekw+(i+1)+" "+nodeprobkw+"("+detprobkw+")"); //basic d1 prob(pd)
				writer.newLine();
				//writer.write(repeatnodeprekw+" "+mitnnodekw+(i+1)+" "+nodeprobkw+"(1)"); //repeat m1 prob(0) {hardcoded mitigation}
				//writer.write(repeatnodeprekw+" "+mitnnodekw+(i+1)+" "+nodeprobkw+"("+((mitnode == "") ? "0" : commonprobkw)+")"); //repeat m1 prob(p)
				//writer.write(repeatnodeprekw+" "+mitnnodekw+(i+1)+" "+nodeprobkw+"("+((mitnode == "") ? "p" : commonprob)+")"); //repeat m1 prob(p)
				writer.write(repeatnodeprekw+" "+mitnnodekw+(i+1)+" "+nodeprobkw+"("+mitprobkw+")"); //basic m1 prob(pm)
				writer.newLine();
				writer.write(andkw+" "+andvakw+(i+1)+" "+vulnnodekw+(i+1)+" "+attnodekw+(i+1)); //and va1 v1 a1
				writer.newLine();
				writer.write(andkw+" "+anddmkw+(i+1)+" "+detnodekw+(i+1)+" "+mitnnodekw+(i+1)); //and dm1 d1 m1
				writer.newLine();
				writer.write(notkw+" "+notanddmkw+(i+1)+" "+anddmkw+(i+1)); //not ndm1 dm1
				writer.newLine();
				writer.write(andkw+" "+andvadmkw+(i+1)+" "+andvakw+(i+1)+" "+notanddmkw+(i+1)); //and vadm1 va1 ndm1
				writer.newLine();
						
			}
			writer.write(orkw+" "+ortopkw+"1"+ " "); //or o1 
			for(int i = 0; i< results.size(); i++){
				writer.write(andvadmkw+(i+1)+" "); //vadm1 vadm2 vadm3...
			}
			writer.newLine();
			writer.write(endkw); //end
			writer.newLine();
			writer.newLine();
			writer.newLine();
			writer.write(bindkw); //bind
			writer.newLine();
			writer.write(commonprobkw+" "+commonprobval); //p .5
			writer.newLine();
			writer.write(endkw); //end
			writer.newLine();
			writer.newLine();
			writer.newLine();
			writer.write(varkw+" "+hvactprobkw+"1"+" "+sysprobkw+"("+faulttreevactkw+"1"+")"); //var Phvact1 sysprob(hvact1)
			writer.newLine();
			writer.write(expressionkw+" "+hvactprobkw+"1"); //expr Phvact1
			writer.newLine();
			//writer.write(endkw); //end
			writer.newLine();
			writer.newLine();
			//added for the bimpt loop node v
			for (int i = 0; i < results.size(); i++) {
				writer.write(expressionkw+" "+bimptkw+"("+bimpttimeval+";"+faulttreevactkw+"1"+","+vulnnodekw+(i+1)+")"); //expr bimpt(2,hvact,v)
				writer.newLine();
			}
			writer.newLine();
			/*
			//added for the bimpt loop node a
			for (int i = 0; i < results.size(); i++) {
				writer.write(expressionkw+" "+bimptkw+"("+bimpttimeval+";"+faulttreevactkw+"1"+","+attnodekw+(i+1)+")"); //expr bimpt(2,hvact,v)
				writer.newLine();
			}
			writer.newLine();
			//added for the bimpt loop node d
			for (int i = 0; i < results.size(); i++) {
				writer.write(expressionkw+" "+bimptkw+"("+bimpttimeval+";"+faulttreevactkw+"1"+","+detnodekw+(i+1)+")"); //expr bimpt(2,hvact,v)
				writer.newLine();
			}
			writer.newLine();
			//added for the bimpt loop node m
			for (int i = 0; i < results.size(); i++) {
				writer.write(expressionkw+" "+bimptkw+"("+bimpttimeval+";"+faulttreevactkw+"1"+","+mitnnodekw+(i+1)+")"); //expr bimpt(2,hvact,v)
				writer.newLine();
			}*/
			
			writer.newLine();
			writer.newLine();
			writer.write(endkw); //end
			//close file writer   
			try {writer.close();} catch (Exception ex) {}
			
		} catch (IOException e) {
			e.printStackTrace();
		} catch (Exception e) {
			e.printStackTrace();
		}
	
	}
	
	private static String getProbVal(String defaultVal, String vulnCVEId) throws SQLException, ClassNotFoundException{
		String probVal = null; 
		Connection conn = null;
        PreparedStatement pst = null;
        ResultSet rs = null;
        //query.setMaxResults(1);
        String strCVSSProbqry = "select max(VulnCVSSBaseScore/10) as ProbVal from vulndbcvss where VulnCVE like '%"+vulnCVEId+"%'";
        try {
			conn = getMySQLConn();
			pst = conn.prepareStatement(strCVSSProbqry);
			rs = pst.executeQuery();
			while(rs.next()){
				probVal = rs.getString("ProbVal");
			}
			conn.close();
			pst.close();
			rs.close();
        }catch (SQLException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}catch (ClassNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
        return (probVal == null) ? defaultVal : probVal;
	}
	
	
	private static Connection getMySQLConn() throws SQLException, ClassNotFoundException{
		 Class.forName(mysqldbClass);
        Connection conn = DriverManager.getConnection(mysqldbUrl+mysqldbname, mysqluser, mysqlpw);
		return conn;
	}
	
	private static String deNuller(String str) {
		return (str == null) ? "" : str;
	}
	
	private static String nodeProb(String str) {
		return (str == null) ? "0" : str;
	}

}//end class
