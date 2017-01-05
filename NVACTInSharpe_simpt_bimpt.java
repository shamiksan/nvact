/**
 * 
 */
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


public class NVACTInSharpe_simpt_bimpt {

	private static String mysqluser = "vuser";
    private static String mysqlpw = "vu@ms123";
    private static String mysqldbname = "vactdb";
    private static String mysqldbUrl = "jdbc:mysql://localhost:3310/";
    private static String mysqldbClass = "com.mysql.jdbc.Driver";
    private static String hvactOutputDir = "D:\\Eclipsespace\\VACT\\output\\InputSharpe\\";
    private static String hvactSharpeFilename = "nvactSharpe";
   
    
	public static void main(String[] args) {
		final long startTime = System.nanoTime();
		
		 	Connection conn = null;
	        PreparedStatement pst = null;
	        ResultSet rs = null;
	        
	        String strHostsqry = "select TargetIP, seqno from vact_hosts where NetworkID = 1 order by seqno ";
	        ArrayList<String[]> hosts= new ArrayList<String[]>(); 
		try {
			conn = getMySQLConn();
			pst = conn.prepareStatement(strHostsqry);
			rs = pst.executeQuery();
			ResultSetMetaData mtD = rs.getMetaData();
			
			//ArrayList<String[]> hosts= new ArrayList<String[]>(); 
			int numberOfColumns = mtD.getColumnCount();
			//System.out.println("The no. of columns is: "+ numberOfColumns);
			while (rs.next()){
			    String[] row = new String[numberOfColumns];
			    for (int i = 0; i < numberOfColumns; i++){
			    	row[i] = (String) rs.getObject(i+1);
			    }
			    hosts.add(row);
			}
			
			
		createNVACTSharpeInput(hosts);	
			
		} catch (SQLException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (ClassNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		final long duration = System.nanoTime() - startTime;
		System.out.println("---Execution Time(sec) ||---"+ duration/1000000000.0+"---|| ");
	}//end main
	
	private static void createNVACTSharpeInput(ArrayList<String[]> hosts) {
		//keywords for SHARPE input
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
		final String hvactprobkw =   "phvact";
		final String commonprobkw =   "p";
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
		final String relgraphkw =   "relgraph";
		final String attgraphnamekw =   "nvactgraph";
		final String variablekw =   "var";
		final String probtopeventname =   "ProbAttackGoal_0";
		final String simptkw =   "simpt";
		final String bimptkw =   "bimpt";
		final String bimpttimeval =   "2";
		final String bimpttimevar =   "q";
		
		
	// TODO Run query for individual vact , load data structures with query data
		
	//-----------------------------------------------------------
		BufferedWriter writer;
		// output to file
		try {
			Date sysdate = new Date();
			SimpleDateFormat ft = new SimpleDateFormat ("dd-MM-yyyy-hh-mm-ss");
			String strdate = ft.format(sysdate);
			//System.out.println("The time now is: "+strdate);
			writer = new BufferedWriter(new OutputStreamWriter(
			          new FileOutputStream(hvactOutputDir+hvactSharpeFilename+"_"+"bimpt_"+strdate.toString()+".flt"), "utf-8"));
			writer.newLine();
			writer.write("format 8 ");
			writer.newLine();
			writer.write("factor on");
			writer.newLine();
			writer.newLine();
			
			writer.write(bindkw); //bind
			writer.newLine();
			writer.write(commonprobkw+" "+commonprobval); //p .5
			writer.newLine();
			writer.write(endkw); //end
			//writer.newLine();
			writer.newLine();
			writer.newLine();
			
			//now start for loop with no. of hosts
			for(String[] hostrow: hosts){
				//System.out.println("\t"+ deNuller(hostrow[0])+" --  "+"\t"+ deNuller(hostrow[1])+"  ");
				//start query to db
				ArrayList<String[]> hostDetails = getHostDetails(deNuller(hostrow[0]));
				//the columns are in order dCVE, aCVE, vCVE
				
				writer.write("* hvact for "+deNuller(hostrow[0])+" - attack tree for a target host in the lower level");
				writer.newLine();
				writer.write(faulttreekw+" "+faulttreevactkw+deNuller(hostrow[1])); //start with naming the fault tree for host vact in top line -- ftree hvact1
				writer.newLine();
				for (int i = 0; i < hostDetails.size(); i++) {
					String vulnnode = null;
					String attnode = null;
					String detnode = null;
					String mitnode = null;
					String commonprob = null;
					String[] resrow = hostDetails.get(i);
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
					writer.write(nodeprekw+" "+vulnnodekw+(i+1)+" "+nodeprobkw+"("+((vulnnode == "") ? "p" : commonprob)+")"); //basic v1 prob(q)
					writer.newLine();
					writer.write(nodeprekw+" "+attnodekw+(i+1)+" "+nodeprobkw+"("+((attnode == "") ? "p" : commonprob)+")"); //basic a1 prob(q)
					writer.newLine();
					writer.write(nodeprekw+" "+detnodekw+(i+1)+" "+nodeprobkw+"("+((detnode == "") ? "p" : commonprob)+")"); //repeat d1 prob(q)
					writer.newLine();
					writer.write(repeatnodeprekw+" "+mitnnodekw+(i+1)+" "+nodeprobkw+"("+((mitnode == "") ? "p" : commonprob)+")"); //repeat m1 prob(q)
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
				writer.write(orkw+" "+ortopkw+deNuller(hostrow[1])+ " "); //or o1 ..check if or gate
				for(int i = 0; i< hostDetails.size(); i++){
					writer.write(andvadmkw+(i+1)+" "); //vadm1 vadm2 vadm3...
				}
				writer.newLine();
				writer.write(endkw); //end
				//writer.newLine();
				writer.newLine();
				writer.newLine();
				
					
				writer.write("echo Probability of attack success for host : "+deNuller(hostrow[0])+" ");
				writer.newLine();
				writer.write(bindkw+" "+hvactprobkw+deNuller(hostrow[1])+" "+sysprobkw+"("+faulttreevactkw+deNuller(hostrow[1])+")"); //bind phvact1 sysprob(hvact1)
				writer.newLine();
				writer.write(expressionkw+" "+hvactprobkw+deNuller(hostrow[1])); //expr phvact1 
				writer.newLine();
				writer.newLine();
				/*
				//added for the simpt loop
				for (int i = 0; i < hostDetails.size(); i++) {
					writer.write(expressionkw+" "+simptkw+"("+faulttreevactkw+deNuller(hostrow[1])+","+vulnnodekw+(i+1)+")");
					writer.newLine();
				}
				writer.newLine();
				writer.newLine(); **/ //we have bimpt so simpt not needed see Trivedi paper
				
				//added for the bimpt loop
				for (int i = 0; i < hostDetails.size(); i++) {
					writer.write(expressionkw+" "+bimptkw+"("+bimpttimevar+";"+faulttreevactkw+deNuller(hostrow[1])+","+vulnnodekw+(i+1)+")"); //expr bimpt(2,hvact,v)
					writer.newLine();
				}
				
				writer.newLine();
				writer.newLine();
				writer.newLine();
				
			}//end for loop with no. of hosts
			
			
			
		/*	writer.write("* relgraph == attack graph in the upper level");
			writer.newLine();
			writer.write(relgraphkw+" "+attgraphnamekw+"1"); //relgraph nvactgraph1 take 1 as network id
			writer.newLine();
			ArrayList<String[]> hostTop = getNetworkTopology(); 
			for(String[] hostVtx : hostTop){
				writer.write(deNuller(hostVtx[0])+" "+deNuller(hostVtx[1])+" "+nodeprobkw+"("+hvactprobkw+deNuller(hostVtx[1])+")");//	0 1 prob(phvact1)
				writer.newLine();
			}
			writer.write(endkw);//end
			writer.newLine();
			writer.newLine();
			writer.write("echo Probability of Attack Goal Success:");
			writer.newLine();
			writer.write(variablekw+" "+probtopeventname+" "+sysprobkw+"("+attgraphnamekw+"1"+")");//	var ProbAttackGoal_0 sysprob(nvactgraph1)
			writer.newLine();
			writer.write(expressionkw+" "+probtopeventname);//	expr ProbTopEvent_0
			writer.newLine();
			writer.write(endkw);//end
			writer.newLine();*/
			
			writer.write(endkw); //end - to be commented otherwise
			
			//close file writer   
			try {writer.close();} catch (Exception ex) {}
		} catch (IOException e) {
			e.printStackTrace();
		} catch (Exception e) {
			e.printStackTrace();
		}
	
	}//end method
	
	
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
	
	
	private static ArrayList<String[]> getHostDetails (String hostIP){
		Connection conn = null;
	    PreparedStatement pst = null;
	    ResultSet rs = null;
	    String strHostVACTqry = " select distinct(d.ReferenceDetails) as dCVE, a.RefDetails as aCVE, r.VulnRefDetails as vCVE from " +
				" vulndbref r inner join vulndb v on r.NessPluginId = v.NessPluginId " +
				" left join vact_meta_mod_refs a on r.VulnRefDetails = a.RefDetails " +
				" left join vact_snort_rules_ref d on r.VulnRefDetails = d.ReferenceDetails " +
				" where r.VulnRefType = 'CVE' " +
				" and v.vulnsoln not in ( '' ,  'n/a') " +
				" and v.TargetIP = '"+hostIP+"' " +
				" and r.VulnRefDetails in (select r.vulnrefdetails " +
					"   from vulndbref  r inner join vulndb v " +
					"	on r.NessPluginId = v.NessPluginId " +
					"	where r.VulnRefType = 'CVE' " +
					"	and v.VulnRiskfactor not in('None', '') " +
					"    ) ";
	    
	    ArrayList<String> columns = new ArrayList<String>();
		ArrayList<String[]> results= new ArrayList<String[]>(); 
		try {
			conn = getMySQLConn();
			pst = conn.prepareStatement(strHostVACTqry);
			rs = pst.executeQuery();
			ResultSetMetaData mtD = rs.getMetaData();
			int numberOfColumns = mtD.getColumnCount();
			//System.out.println("The no. of columns is: "+ numberOfColumns);
			for(int i = 1; i<= numberOfColumns; i++){
			    columns.add(mtD.getColumnName(i));
			//    System.out.print("\t"+mtD.getColumnName(i).toString()+"\t");
			}
			while (rs.next()){
			    String[] row = new String[numberOfColumns];
			    for (int i = 0; i < numberOfColumns; i++){
			    	row[i] = (String) rs.getObject(i+1);
			    }
			    results.add(row);
			}
							        
			} catch (SQLException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (ClassNotFoundException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}finally{//release DB resources
				try{if(rs != null) rs.close();}
		        catch(SQLException sqlEx){System.out.println("Error: disconnect");}   
		        try{if(pst != null) pst.close();}
		        catch(SQLException sqlEx){System.out.println("Error: disconnect");}   
		        try{if(conn != null) conn.close();}
		        catch(SQLException sqlEx){System.out.println("Error: disconnect");}
			}//end finally
		return results;
	}
	
	
	private static ArrayList<String[]> getNetworkTopology (){
		Connection cnn = null;
	    PreparedStatement pstmt = null;
	    ResultSet rsst = null;
	    String strtopqry = "select startvx, endvx from vact_hosts_topology where NetworkID = 1 ";
	    ArrayList<String[]> arrLstTop= new ArrayList<String[]>(); 
		try {
			cnn = getMySQLConn();
			pstmt = cnn.prepareStatement(strtopqry);
			rsst = pstmt.executeQuery();
			ResultSetMetaData mtD = rsst.getMetaData();
			int numberOfColumns = mtD.getColumnCount();
			while (rsst.next()){
			    String[] row = new String[numberOfColumns];
			    for (int i = 0; i < numberOfColumns; i++){
			    	row[i] = (String) rsst.getObject(i+1);
			    }
			    arrLstTop.add(row);
			}
		}catch(SQLException e){
			e.printStackTrace();
		}catch (Exception e) {
			e.printStackTrace();
		}finally{ //release DB resources
			try{if(rsst != null) rsst.close();
	        } catch(SQLException sqlEx){ System.out.println("Error: disconnect");}   
	        try{if(pstmt != null) pstmt.close();
	        } catch(SQLException sqlEx){ System.out.println("Error: disconnect");}   
	        try{if(cnn != null) cnn.close();
	        } catch(SQLException sqlEx){ System.out.println("Error: disconnect");}
		}//end finally
		  return arrLstTop;
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

}
