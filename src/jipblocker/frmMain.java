/*
 * Copyright (C) 2015 SaEeD
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */
package jipblocker;

import java.awt.Color;
import java.awt.Toolkit;
import java.awt.datatransfer.Clipboard;
import java.awt.datatransfer.StringSelection;
import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.swing.JFileChooser;
import javax.swing.JOptionPane;
import javax.swing.table.DefaultTableModel;

/**
 *
 * @author SaEeD
 */
public class frmMain extends javax.swing.JFrame {

    //Regulat expression pattern to detect ip v4 addresses 
    private static final String IP_REGEX = "\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}";
    private static String Keyword_txt_REGEX;
    private static HashMap<String,  Integer > ipaddresses = new HashMap<String, Integer>();
    private ArrayList<String> blockList = new ArrayList<>();
    
    public frmMain() {
        initComponents();
        
    }
///////////////validating log file by looking for "sshd" string
    private boolean validate_logfile(File logfile) throws IOException
{

    System.out.println("[+]Validating Log file....");

    int count=0;
    BufferedReader stdin = new BufferedReader(new FileReader(logfile));
    String read;
    while((read = stdin.readLine()) != null)
    {			
        if(read.contains("sshd") || read.contains("GET") || read.contains("HTTP"))
        {
                count++;
        }
        if(count >= 3)
        {
                lblStatus.setText("[+]Log file seems to be valid :-)");
                return true;
        }
    }		
    stdin.close();		
    return false;
    }//-- end of validate function
    
/////////////Detect Failure Login attempts
    public  void detect_ip_from_keyword(File logfile, String Keyword)throws IOException
    {
        if(Keyword == null)
        {
            Keyword_txt_REGEX = "Failed password";
        }else{
            Keyword_txt_REGEX = Keyword;
            System.out.println("String to Search for:" + Keyword);
        }
        ipaddresses.clear();
        
        lblStatus.setText("[+]Reading Log file contents, please wait...");
        BufferedReader stdin =  new BufferedReader(new FileReader(logfile));

        Pattern pattern_failure = Pattern.compile(Keyword_txt_REGEX,Pattern.CASE_INSENSITIVE);
        Pattern pattern_ip = Pattern.compile(IP_REGEX,Pattern.CASE_INSENSITIVE);

        String input,ip;

        while((input = stdin.readLine())!=null)
        {
                //Searching for Failed password String	
                Matcher matcher = pattern_failure.matcher(input);
                        if(matcher.find())
                        {
                                //System.out.println("####found### "+ matcher.group());

                                //Searching for ip addresses in failure line
                                Matcher ip_matcher = pattern_ip.matcher(input);
                                if(ip_matcher.find())
                                {
                                        ip = ip_matcher.group();
                                        //System.out.println("IP address: " + ip);

                                        //Check if ip is already added to list increase its attempt times
                                        //otherwise add the new ip to list
                                        if(ipaddresses.containsKey(ip))
                                        {
                                                int count = ipaddresses.get(ip);
                                                count++;
                                                ipaddresses.remove(ip);
                                                ipaddresses.put(ip, count);


                                        }else{
                                                ipaddresses.put(ip, 1);
                                        }//-- end else
                                }
                        }// -- end searching if				
        }//-- End of while loop
        lblStatus.setText("[+]Searching process completed.");

        //System.out.println(ipaddresses);
        stdin.close();

    }//-- end of detect_failure_login

////////////Generating Report console
    private void gen_report_console()
    {
            Set mySet = ipaddresses.entrySet();

            System.out.println("[+]Generating report.");
            System.out.println("=======================================================");
            System.out.println("IP Address\t\tNumber of Failure Attempts");
            System.out.println("____________\t\t__________________________");
            Iterator i = mySet.iterator();
            while(i.hasNext())
            {
                    Map.Entry map = (Map.Entry)i.next();
                    System.out.print(map.getKey()+"\t\t\t" + map.getValue());
                    int x = Integer.parseInt(map.getValue().toString());
                    if(x > 10 )
                    {
                            System.out.print("\t\t!! BruteForce Attack Detected !!");
                    }
                    System.out.println();
            }
            System.out.println("=======================================================");


    }// End of report
    
    ////////////Read Apache Access.log file and add count number of connections by ip addresses
   private void Read_Apache_Log(File logfile) throws IOException
   {
            lblStatus.setText("[+]Reading Log file contents, please wait...");
            ipaddresses.clear();
            
            BufferedReader stdin =  new BufferedReader(new FileReader(logfile));
            Pattern pattern_ip = Pattern.compile(IP_REGEX,Pattern.CASE_INSENSITIVE);

            String input,ip;

            while((input = stdin.readLine())!=null)
            {
                //Searching for ip addresses in failure line
                Matcher ip_matcher = pattern_ip.matcher(input);
                if(ip_matcher.find())
                {
                        ip = ip_matcher.group();
                        //System.out.println("IP address: " + ip);

                        //Check if ip is already added to list increase its attempt times
                        //otherwise add the new ip to list
                        if(ipaddresses.containsKey(ip))
                        {
                                int count = ipaddresses.get(ip);
                                count++;
                                ipaddresses.remove(ip);
                                ipaddresses.put(ip, count);
                        }else{
                                ipaddresses.put(ip, 1);
                        }//-- end else
                }
                            				
            }//-- End of while loop
            lblStatus.setText("[+]Searching process completed.");

            //System.out.println(ipaddresses);
            stdin.close();
   }
   ////////////Fill table with new ip addresses
   private void gen_Table_Report()
   {
       Set mySet = ipaddresses.entrySet();
       DefaultTableModel model =  (DefaultTableModel) IPTable.getModel();
       model.setRowCount(0);
       
       revalidate();

            Iterator i = mySet.iterator();
            while(i.hasNext())
            {
                    Map.Entry map = (Map.Entry)i.next();
                    //System.out.print(map.getKey()+"\t\t\t" + map.getValue());
                    model.addRow(new Object[]{map.getKey(), map.getValue(),"",null,true});
            }
            if(model.getRowCount() > 0)
            {
                btnLocate.setEnabled(true);
                btnGenerateIptablesFilter.setEnabled(true);
                btnGenerateApacheFilter.setEnabled(true);
            }else{
                btnLocate.setEnabled(false);
                btnGenerateIptablesFilter.setEnabled(false);
                btnGenerateApacheFilter.setEnabled(false);
            }
            //clear the static value
            
   }
    /**
     * This method is called from within the constructor to initialize the form. WARNING: Do NOT modify this code. The content of this method is always regenerated by the Form Editor.
     */
    @SuppressWarnings("unchecked")
    // <editor-fold defaultstate="collapsed" desc="Generated Code">//GEN-BEGIN:initComponents
    private void initComponents() {

        ContextMenu = new javax.swing.JPopupMenu();
        itmCopyToClipboard = new javax.swing.JMenuItem();
        itmLocateOrigin = new javax.swing.JMenuItem();
        itmGenerateFilter = new javax.swing.JMenuItem();
        buttonGroup1 = new javax.swing.ButtonGroup();
        DlgGenFilter = new javax.swing.JDialog();
        jPanel4 = new javax.swing.JPanel();
        jScrollPane2 = new javax.swing.JScrollPane();
        txtReportArea = new javax.swing.JTextArea();
        btnSaveToFile = new javax.swing.JButton();
        btnCloseDlgFrm = new javax.swing.JButton();
        DlgContextMenu = new javax.swing.JPopupMenu();
        DlgItmCopyToClipboard = new javax.swing.JMenuItem();
        jPanel1 = new javax.swing.JPanel();
        jPanel2 = new javax.swing.JPanel();
        txtRegExp = new javax.swing.JTextField();
        btnCustSearch = new javax.swing.JButton();
        jScrollPane1 = new javax.swing.JScrollPane();
        IPTable = new javax.swing.JTable();
        btnReport = new javax.swing.JButton();
        btnLocate = new javax.swing.JButton();
        btnGenerateIptablesFilter = new javax.swing.JButton();
        btnGenerateApacheFilter = new javax.swing.JButton();
        btnReset = new javax.swing.JButton();
        jPanel3 = new javax.swing.JPanel();
        jLabel1 = new javax.swing.JLabel();
        txtLogfilePath = new javax.swing.JTextField();
        btnBrowse = new javax.swing.JButton();
        RadioBtnSSHLog = new javax.swing.JRadioButton();
        RadioBtnApache = new javax.swing.JRadioButton();
        RadioBtnCustom = new javax.swing.JRadioButton();
        chkBoxValidate = new javax.swing.JCheckBox();
        lblStatus = new javax.swing.JLabel();

        itmCopyToClipboard.setText("Copy IP to Clipboard");
        itmCopyToClipboard.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                itmCopyToClipboardActionPerformed(evt);
            }
        });
        ContextMenu.add(itmCopyToClipboard);

        itmLocateOrigin.setText("Locate Origin");
        itmLocateOrigin.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                itmLocateOriginActionPerformed(evt);
            }
        });
        ContextMenu.add(itmLocateOrigin);

        itmGenerateFilter.setText("Generate Filter");
        itmGenerateFilter.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                itmGenerateFilterActionPerformed(evt);
            }
        });
        ContextMenu.add(itmGenerateFilter);

        DlgGenFilter.setDefaultCloseOperation(javax.swing.WindowConstants.DISPOSE_ON_CLOSE);
        DlgGenFilter.setTitle("Filter Generator");
        DlgGenFilter.setLocationByPlatform(true);
        DlgGenFilter.setMinimumSize(new java.awt.Dimension(440, 550));
        DlgGenFilter.setModal(true);

        txtReportArea.setEditable(false);
        txtReportArea.setColumns(20);
        txtReportArea.setForeground(new java.awt.Color(51, 51, 255));
        txtReportArea.setRows(5);
        txtReportArea.setText("#### Auto Generated Block List ####\n\n\n");
        txtReportArea.setComponentPopupMenu(DlgContextMenu);
        jScrollPane2.setViewportView(txtReportArea);

        btnSaveToFile.setText("Save to File");
        btnSaveToFile.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                btnSaveToFileActionPerformed(evt);
            }
        });

        btnCloseDlgFrm.setText("Close");
        btnCloseDlgFrm.setMaximumSize(new java.awt.Dimension(99, 30));
        btnCloseDlgFrm.setMinimumSize(new java.awt.Dimension(99, 50));
        btnCloseDlgFrm.setPreferredSize(new java.awt.Dimension(99, 25));
        btnCloseDlgFrm.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                btnCloseDlgFrmActionPerformed(evt);
            }
        });

        javax.swing.GroupLayout jPanel4Layout = new javax.swing.GroupLayout(jPanel4);
        jPanel4.setLayout(jPanel4Layout);
        jPanel4Layout.setHorizontalGroup(
            jPanel4Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel4Layout.createSequentialGroup()
                .addContainerGap()
                .addGroup(jPanel4Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(jScrollPane2, javax.swing.GroupLayout.DEFAULT_SIZE, 392, Short.MAX_VALUE)
                    .addGroup(jPanel4Layout.createSequentialGroup()
                        .addComponent(btnSaveToFile)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(btnCloseDlgFrm, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addGap(0, 0, Short.MAX_VALUE)))
                .addContainerGap())
        );
        jPanel4Layout.setVerticalGroup(
            jPanel4Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel4Layout.createSequentialGroup()
                .addContainerGap()
                .addComponent(jScrollPane2, javax.swing.GroupLayout.PREFERRED_SIZE, 444, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                .addGroup(jPanel4Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(btnSaveToFile, javax.swing.GroupLayout.PREFERRED_SIZE, 41, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(btnCloseDlgFrm, javax.swing.GroupLayout.PREFERRED_SIZE, 41, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addGap(0, 0, 0))
        );

        javax.swing.GroupLayout DlgGenFilterLayout = new javax.swing.GroupLayout(DlgGenFilter.getContentPane());
        DlgGenFilter.getContentPane().setLayout(DlgGenFilterLayout);
        DlgGenFilterLayout.setHorizontalGroup(
            DlgGenFilterLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(DlgGenFilterLayout.createSequentialGroup()
                .addContainerGap()
                .addComponent(jPanel4, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                .addContainerGap())
        );
        DlgGenFilterLayout.setVerticalGroup(
            DlgGenFilterLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(DlgGenFilterLayout.createSequentialGroup()
                .addComponent(jPanel4, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addGap(0, 16, Short.MAX_VALUE))
        );

        DlgItmCopyToClipboard.setText("Copy to Clipboard");
        DlgItmCopyToClipboard.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                DlgItmCopyToClipboardActionPerformed(evt);
            }
        });
        DlgContextMenu.add(DlgItmCopyToClipboard);

        setDefaultCloseOperation(javax.swing.WindowConstants.EXIT_ON_CLOSE);
        setTitle("IP address Blocker V0.1");
        setLocationByPlatform(true);
        setMaximumSize(null);
        setResizable(false);

        jPanel2.setBorder(javax.swing.BorderFactory.createTitledBorder("Customized Search"));

        txtRegExp.setForeground(new java.awt.Color(153, 51, 0));
        txtRegExp.setHorizontalAlignment(javax.swing.JTextField.CENTER);
        txtRegExp.setText("Keyword to be search to find IP");
        txtRegExp.setToolTipText("Please refer to Java Regular Expression documentation.");

        btnCustSearch.setText("New Keyword Search");
        btnCustSearch.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                btnCustSearchActionPerformed(evt);
            }
        });

        javax.swing.GroupLayout jPanel2Layout = new javax.swing.GroupLayout(jPanel2);
        jPanel2.setLayout(jPanel2Layout);
        jPanel2Layout.setHorizontalGroup(
            jPanel2Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel2Layout.createSequentialGroup()
                .addContainerGap()
                .addGroup(jPanel2Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(btnCustSearch, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                    .addComponent(txtRegExp))
                .addContainerGap())
        );
        jPanel2Layout.setVerticalGroup(
            jPanel2Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel2Layout.createSequentialGroup()
                .addComponent(txtRegExp, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(btnCustSearch))
        );

        IPTable.setModel(new javax.swing.table.DefaultTableModel(
            new Object [][] {

            },
            new String [] {
                "IP Address", "Number of attempts", "Origin Country", "Country Flag", "Block Range?"
            }
        ) {
            Class[] types = new Class [] {
                java.lang.String.class, java.lang.Integer.class, java.lang.String.class, java.lang.Object.class, java.lang.Boolean.class
            };
            boolean[] canEdit = new boolean [] {
                false, false, false, false, true
            };

            public Class getColumnClass(int columnIndex) {
                return types [columnIndex];
            }

            public boolean isCellEditable(int rowIndex, int columnIndex) {
                return canEdit [columnIndex];
            }
        });
        IPTable.setComponentPopupMenu(ContextMenu);
        IPTable.setSelectionMode(javax.swing.ListSelectionModel.SINGLE_SELECTION);
        jScrollPane1.setViewportView(IPTable);
        if (IPTable.getColumnModel().getColumnCount() > 0) {
            IPTable.getColumnModel().getColumn(0).setPreferredWidth(10);
            IPTable.getColumnModel().getColumn(1).setPreferredWidth(30);
            IPTable.getColumnModel().getColumn(3).setCellRenderer(new MyCellRenderer());
        }

        btnReport.setText("Generate Report");
        btnReport.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                btnReportActionPerformed(evt);
            }
        });

        btnLocate.setText("Locate all IP(s) Origin ");
        btnLocate.setEnabled(false);
        btnLocate.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                btnLocateActionPerformed(evt);
            }
        });

        btnGenerateIptablesFilter.setText("Generate IPTABLES Filter");
        btnGenerateIptablesFilter.setEnabled(false);
        btnGenerateIptablesFilter.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                btnGenerateIptablesFilterActionPerformed(evt);
            }
        });

        btnGenerateApacheFilter.setText("Generate .htaccess Filter");
        btnGenerateApacheFilter.setEnabled(false);
        btnGenerateApacheFilter.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                btnGenerateApacheFilterActionPerformed(evt);
            }
        });

        btnReset.setText("Reset!");
        btnReset.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                btnResetActionPerformed(evt);
            }
        });

        jPanel3.setBorder(javax.swing.BorderFactory.createTitledBorder("Select Log File"));

        jLabel1.setText("Enter log file path:");

        txtLogfilePath.setEditable(false);
        txtLogfilePath.setBackground(new java.awt.Color(255, 255, 255));
        txtLogfilePath.setForeground(Color.BLACK);
        txtLogfilePath.setText("File name....");

        btnBrowse.setText("Browse");
        btnBrowse.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                btnBrowseActionPerformed(evt);
            }
        });

        buttonGroup1.add(RadioBtnSSHLog);
        RadioBtnSSHLog.setText("Auth.log OR Message.log");
        RadioBtnSSHLog.setToolTipText("Linux /var/log/auth.log file");
        RadioBtnSSHLog.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                RadioBtnSSHLogActionPerformed(evt);
            }
        });

        buttonGroup1.add(RadioBtnApache);
        RadioBtnApache.setSelected(true);
        RadioBtnApache.setText("Apache2/Access.log");
        RadioBtnApache.setToolTipText("Linux /var/log/apache2/access.log file");
        RadioBtnApache.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                RadioBtnSSHLogActionPerformed(evt);
            }
        });

        buttonGroup1.add(RadioBtnCustom);
        RadioBtnCustom.setText("Custom Log file");
        RadioBtnCustom.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                RadioBtnCustomActionPerformed(evt);
            }
        });

        chkBoxValidate.setSelected(true);
        chkBoxValidate.setText("Validate Log File");

        javax.swing.GroupLayout jPanel3Layout = new javax.swing.GroupLayout(jPanel3);
        jPanel3.setLayout(jPanel3Layout);
        jPanel3Layout.setHorizontalGroup(
            jPanel3Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel3Layout.createSequentialGroup()
                .addContainerGap()
                .addComponent(jLabel1, javax.swing.GroupLayout.PREFERRED_SIZE, 118, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(jPanel3Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(jPanel3Layout.createSequentialGroup()
                        .addComponent(RadioBtnCustom)
                        .addGap(0, 0, Short.MAX_VALUE))
                    .addGroup(jPanel3Layout.createSequentialGroup()
                        .addGroup(jPanel3Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addComponent(txtLogfilePath, javax.swing.GroupLayout.PREFERRED_SIZE, 440, javax.swing.GroupLayout.PREFERRED_SIZE)
                            .addGroup(jPanel3Layout.createSequentialGroup()
                                .addComponent(RadioBtnSSHLog)
                                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                .addComponent(RadioBtnApache)
                                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                .addComponent(chkBoxValidate)))
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(btnBrowse, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)))
                .addContainerGap())
        );
        jPanel3Layout.setVerticalGroup(
            jPanel3Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel3Layout.createSequentialGroup()
                .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                .addGroup(jPanel3Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(jLabel1)
                    .addComponent(txtLogfilePath, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(btnBrowse))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(jPanel3Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(RadioBtnSSHLog)
                    .addComponent(RadioBtnApache)
                    .addComponent(chkBoxValidate))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(RadioBtnCustom))
        );

        javax.swing.GroupLayout jPanel1Layout = new javax.swing.GroupLayout(jPanel1);
        jPanel1.setLayout(jPanel1Layout);
        jPanel1Layout.setHorizontalGroup(
            jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel1Layout.createSequentialGroup()
                .addGroup(jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING, false)
                    .addComponent(jPanel2, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                    .addComponent(jScrollPane1)
                    .addGroup(jPanel1Layout.createSequentialGroup()
                        .addComponent(btnReport, javax.swing.GroupLayout.PREFERRED_SIZE, 177, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(btnLocate, javax.swing.GroupLayout.PREFERRED_SIZE, 177, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(btnGenerateIptablesFilter)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(btnGenerateApacheFilter))
                    .addComponent(btnReset, javax.swing.GroupLayout.Alignment.LEADING, javax.swing.GroupLayout.PREFERRED_SIZE, 727, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addGap(0, 0, Short.MAX_VALUE))
            .addComponent(jPanel3, javax.swing.GroupLayout.Alignment.TRAILING, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
        );
        jPanel1Layout.setVerticalGroup(
            jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel1Layout.createSequentialGroup()
                .addComponent(jPanel3, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(jPanel2, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(jScrollPane1, javax.swing.GroupLayout.PREFERRED_SIZE, 448, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addGroup(jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(btnReport)
                    .addComponent(btnLocate)
                    .addComponent(btnGenerateIptablesFilter)
                    .addComponent(btnGenerateApacheFilter))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(btnReset))
        );

        lblStatus.setText("[+]Status:...");
        lblStatus.setToolTipText("");
        lblStatus.setBorder(javax.swing.BorderFactory.createBevelBorder(javax.swing.border.BevelBorder.LOWERED));

        javax.swing.GroupLayout layout = new javax.swing.GroupLayout(getContentPane());
        getContentPane().setLayout(layout);
        layout.setHorizontalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addContainerGap()
                .addComponent(jPanel1, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
            .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, layout.createSequentialGroup()
                .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                .addComponent(lblStatus, javax.swing.GroupLayout.PREFERRED_SIZE, 727, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addContainerGap())
        );
        layout.setVerticalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addContainerGap()
                .addComponent(jPanel1, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                .addComponent(lblStatus)
                .addContainerGap())
        );

        pack();
    }// </editor-fold>//GEN-END:initComponents
//==================================================
// Get the log file path
//==================================================
    private void btnBrowseActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnBrowseActionPerformed
        
        JFileChooser myfile = new JFileChooser();
        String filename;
        int retVal = myfile.showOpenDialog(this);
        if(retVal == JFileChooser.APPROVE_OPTION)
            {
                filename = myfile.getSelectedFile().getAbsolutePath();
                txtLogfilePath.setText(filename);
                btnLocate.setEnabled(false);
                btnGenerateIptablesFilter.setEnabled(false);
                btnGenerateApacheFilter.setEnabled(false);
            }
        
    }//GEN-LAST:event_btnBrowseActionPerformed

    private void RadioBtnCustomActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_RadioBtnCustomActionPerformed
        chkBoxValidate.setEnabled(false);
    }//GEN-LAST:event_RadioBtnCustomActionPerformed

    private void RadioBtnSSHLogActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_RadioBtnSSHLogActionPerformed
        chkBoxValidate.setEnabled(true);
    }//GEN-LAST:event_RadioBtnSSHLogActionPerformed

//==================================================
// Generate report button
//==================================================
    private void btnReportActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnReportActionPerformed
        lblStatus.setText("[+]Generating report");
        try
        {
            File m_file = new File(txtLogfilePath.getText());
            if(!m_file.exists())
            {
                lblStatus.setText("[!]Error: Cannot access the file anymore, please relocate it");
                return;
            }
            
            //##############################################
            if(chkBoxValidate.isSelected() && !RadioBtnCustom.isSelected())
            {
                lblStatus.setText("[+]Validating the log file");
                if(!validate_logfile(m_file))
                {
                    lblStatus.setText("[!]Invalid Log file, please choose another file");
                }
            }
            //##############################################
            
            if(RadioBtnSSHLog.isSelected())
            {
                detect_ip_from_keyword(m_file, null);
                gen_report_console();
                gen_Table_Report();
            }
            
            if(RadioBtnApache.isSelected() || RadioBtnCustom.isSelected())
            {
                Read_Apache_Log(m_file);
                gen_report_console();
                gen_Table_Report();
            }
            
            
        }catch(IOException e)
        {
            lblStatus.setText("[!]Fatal exception: " + e.getMessage());
        }
    }//GEN-LAST:event_btnReportActionPerformed

//==================================================
// context menue items implementation
//==================================================
    private void itmCopyToClipboardActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_itmCopyToClipboardActionPerformed
        
        //This would make sure if the sorting changes the order of the rows
        //still we get the correct row value after sorting
        int rowIndex = IPTable.getSelectedRow();
        int row = IPTable.convertRowIndexToModel(rowIndex);
        //////////////////////////////////////////////////
        
        String selectedObject = (String) IPTable.getModel().getValueAt(row, 0);
        String value = (String) IPTable.getModel().getValueAt(row, 2);
        //System.out.println("Selected row " + rowIndex + " value:" + selectedObject + " Value: " + value );
        
        StringSelection stringSelection = new StringSelection (selectedObject);
        Clipboard clpbrd = Toolkit.getDefaultToolkit ().getSystemClipboard ();
        clpbrd.setContents (stringSelection, null);
        
    }//GEN-LAST:event_itmCopyToClipboardActionPerformed

    private void itmLocateOriginActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_itmLocateOriginActionPerformed
        
        //This would make sure if the sorting changes the order of the rows
        //still we get the correct row value after sorting
        int rowIndex = IPTable.getSelectedRow();
        int row = IPTable.convertRowIndexToModel(rowIndex);
        //////////////////////////////////////////////////
        
        String selectedObject = (String) IPTable.getModel().getValueAt(row, 0);
        IPOrigin origin = new IPOrigin(IPTable);
        String name = origin.getCountryName(selectedObject);
        IPTable.setValueAt(name, row, 2);
        IPTable.setValueAt(name, row, 3);
        
    }//GEN-LAST:event_itmLocateOriginActionPerformed

    private void itmGenerateFilterActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_itmGenerateFilterActionPerformed
        
        //This would make sure if the sorting changes the order of the rows
        //still we get the correct row value after sorting
        int rowIndex = IPTable.getSelectedRow();
        int row = IPTable.convertRowIndexToModel(rowIndex);
        //////////////////////////////////////////////////
        
        txtReportArea.setText("#### Auto Generated IPTABLES Block List ####\n\n");
        String selectedIP = (String) IPTable.getModel().getValueAt(row, 0);
        
            if((boolean)IPTable.getValueAt(row, 4))
            {
                int end = selectedIP.lastIndexOf(".");
                selectedIP = selectedIP.substring(0, end+1) + "0/24";
                
            }
        txtReportArea.append("iptables -A INPUT -s " + selectedIP +" -j DROP\n");
        DlgGenFilter.setVisible(true);
        
        
    }//GEN-LAST:event_itmGenerateFilterActionPerformed

//==================================================
// Custom keyword search to find ip
//==================================================
    private void btnCustSearchActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnCustSearchActionPerformed
        
        try
        {
            File m_file = new File(txtLogfilePath.getText());
            if(!m_file.exists())
            {
                lblStatus.setText("[!]Error: Cannot access the file anymore, please relocate it");
                return;
            }
            detect_ip_from_keyword(m_file, txtRegExp.getText());
            gen_report_console();
            gen_Table_Report();
        }catch(IOException e)
        {
            lblStatus.setText("[Exception]: " + e.getMessage());
        }
    }//GEN-LAST:event_btnCustSearchActionPerformed

//==================================================
// Executing new Thread to locate Origin of Listed IPs
//==================================================
    private void btnLocateActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnLocateActionPerformed
        
       try{
           IPOrigin worker = new IPOrigin(IPTable);
           worker.execute();
       }catch(Exception e)
       {
           System.err.println("[!]Exception: " + e.getMessage());
       }
        
    }//GEN-LAST:event_btnLocateActionPerformed

    private void btnGenerateIptablesFilterActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnGenerateIptablesFilterActionPerformed
        
        System.out.println("[+]Getting rows information:");
        if(!blockList.isEmpty())
        {
            blockList.clear();
        }
        for(int i=0; i < IPTable.getRowCount();i++)
        {
            String IpAddr = (String)IPTable.getValueAt(i, 0);
            
            //Check if the subnet block request is checked
            if((boolean)IPTable.getValueAt(i, 4))
            {
                int end = IpAddr.lastIndexOf(".");
                String IpAddrWithSubnet = IpAddr.substring(0, end+1) + "0/24";
                //System.out.println("IP subnet : " + IpAddrWithSubnet);
                blockList.add(IpAddrWithSubnet);
                
            }else{
                //System.out.println("IP: " + IpAddr);
                blockList.add(IpAddr);
            }            
        }
        txtReportArea.setText("#### Auto Generated IPTABLES Block List ####\n\n");
        
        for(String value: blockList)
        {
            txtReportArea.append("iptables -A INPUT -s " + value +" -j DROP\n");
        }
        
        DlgGenFilter.setVisible(true);
        
    }//GEN-LAST:event_btnGenerateIptablesFilterActionPerformed

    private void btnGenerateApacheFilterActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnGenerateApacheFilterActionPerformed
        
        System.out.println("[+]Getting rows information:");
        blockList.clear();
        for(int i=0; i < IPTable.getRowCount();i++)
        {
            String IpAddr = (String)IPTable.getValueAt(i, 0);
            
            //Check if the subnet block request is checked
            if((boolean)IPTable.getValueAt(i, 4))
            {
                int end = IpAddr.lastIndexOf(".");
                String IpAddrWithSubnet = IpAddr.substring(0, end+1) + "0/24";
                //System.out.println("IP subnet : " + IpAddrWithSubnet);
                blockList.add(IpAddrWithSubnet);
                
            }else{
                //System.out.println("IP: " + IpAddr);
                blockList.add(IpAddr);
            }            
        }
        txtReportArea.setText("#### Auto Generated .htaccess Block List ####\n\n");
        txtReportArea.append("<LIMIT GET HEAD POST>\norder allow,deny\n\n");
        
        for(String value: blockList)
        {
            txtReportArea.append("deny from " + value +"\n");
        }
        
        txtReportArea.append("\nallow from all\n</LIMIT>\n");
        DlgGenFilter.setVisible(true);
    }//GEN-LAST:event_btnGenerateApacheFilterActionPerformed

    //Rest all the components
    private void btnResetActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnResetActionPerformed
        btnLocate.setEnabled(false);
        btnGenerateIptablesFilter.setEnabled(false);
        btnGenerateApacheFilter.setEnabled(false);
        
        DefaultTableModel model =  (DefaultTableModel) IPTable.getModel();
        model.setRowCount(0);
        
    }//GEN-LAST:event_btnResetActionPerformed

    
//==================================================
// Dialog box 
//==================================================    
    private void btnCloseDlgFrmActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnCloseDlgFrmActionPerformed
        DlgGenFilter.dispose();
    }//GEN-LAST:event_btnCloseDlgFrmActionPerformed

    private void btnSaveToFileActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnSaveToFileActionPerformed
        
        JFileChooser myfile = new JFileChooser();
        String filename;
        int retVal = myfile.showSaveDialog(this);
        if(retVal == JFileChooser.APPROVE_OPTION)
            {
                BufferedWriter output = null;
            try {
                File file = myfile.getSelectedFile();
                
                if(file.exists())
                {
                    int ret = JOptionPane.showConfirmDialog(this, "File Already Exist, Do you want to overwrite?", "Message", JOptionPane.YES_NO_OPTION , JOptionPane.ERROR_MESSAGE);
                    if(ret == JOptionPane.YES_OPTION)
                    {                        
                        output = new BufferedWriter(new FileWriter(file));
                        output.write(txtReportArea.getText());
                        JOptionPane.showMessageDialog(this, "File Saved!\n" + file.getAbsolutePath());
                    }
                }else{
                    output = new BufferedWriter(new FileWriter(file));
                    output.write(txtReportArea.getText());
                    JOptionPane.showMessageDialog(this, "File Saved!\n" + file.getAbsolutePath());
                }                
                
            } catch (IOException ex) {
                Logger.getLogger(frmMain.class.getName()).log(Level.SEVERE, null, ex);
            } finally {
                try {
                    output.close();
                } catch (IOException ex) {
                    Logger.getLogger(frmMain.class.getName()).log(Level.SEVERE, null, ex);
                }
            }
                
            }
        
        
    }//GEN-LAST:event_btnSaveToFileActionPerformed

    private void DlgItmCopyToClipboardActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_DlgItmCopyToClipboardActionPerformed
        
        String selected = txtReportArea.getSelectedText();
        
        System.out.println("Selected: " + selected);
        StringSelection stringSelection = new StringSelection (selected);
        Clipboard clpbrd = Toolkit.getDefaultToolkit ().getSystemClipboard ();
        clpbrd.setContents (stringSelection, null);
        
    }//GEN-LAST:event_DlgItmCopyToClipboardActionPerformed

    /**
     * @param args the command line arguments
     */
    public static void main(String args[]) {
        /* Set the Nimbus look and feel */
        //<editor-fold defaultstate="collapsed" desc=" Look and feel setting code (optional) ">
        /* If Nimbus (introduced in Java SE 6) is not available, stay with the default look and feel.
         * For details see http://download.oracle.com/javase/tutorial/uiswing/lookandfeel/plaf.html 
         */
        try {
            for (javax.swing.UIManager.LookAndFeelInfo info : javax.swing.UIManager.getInstalledLookAndFeels()) {
                if ("Metal".equals(info.getName())) {
                    javax.swing.UIManager.setLookAndFeel(info.getClassName());
                    break;
                }
            }
        } catch (ClassNotFoundException ex) {
            java.util.logging.Logger.getLogger(frmMain.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (InstantiationException ex) {
            java.util.logging.Logger.getLogger(frmMain.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (IllegalAccessException ex) {
            java.util.logging.Logger.getLogger(frmMain.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (javax.swing.UnsupportedLookAndFeelException ex) {
            java.util.logging.Logger.getLogger(frmMain.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        }
        //</editor-fold>

        /* Create and display the form */
        java.awt.EventQueue.invokeLater(new Runnable() {
            public void run() {
                new frmMain().setVisible(true);
            }
        });
    }

    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JPopupMenu ContextMenu;
    private javax.swing.JPopupMenu DlgContextMenu;
    private javax.swing.JDialog DlgGenFilter;
    private javax.swing.JMenuItem DlgItmCopyToClipboard;
    private javax.swing.JTable IPTable;
    private javax.swing.JRadioButton RadioBtnApache;
    private javax.swing.JRadioButton RadioBtnCustom;
    private javax.swing.JRadioButton RadioBtnSSHLog;
    private javax.swing.JButton btnBrowse;
    private javax.swing.JButton btnCloseDlgFrm;
    private javax.swing.JButton btnCustSearch;
    private javax.swing.JButton btnGenerateApacheFilter;
    private javax.swing.JButton btnGenerateIptablesFilter;
    public static javax.swing.JButton btnLocate;
    private javax.swing.JButton btnReport;
    private javax.swing.JButton btnReset;
    private javax.swing.JButton btnSaveToFile;
    private javax.swing.ButtonGroup buttonGroup1;
    private javax.swing.JCheckBox chkBoxValidate;
    private javax.swing.JMenuItem itmCopyToClipboard;
    private javax.swing.JMenuItem itmGenerateFilter;
    private javax.swing.JMenuItem itmLocateOrigin;
    private javax.swing.JLabel jLabel1;
    private javax.swing.JPanel jPanel1;
    private javax.swing.JPanel jPanel2;
    private javax.swing.JPanel jPanel3;
    private javax.swing.JPanel jPanel4;
    private javax.swing.JScrollPane jScrollPane1;
    private javax.swing.JScrollPane jScrollPane2;
    public static javax.swing.JLabel lblStatus;
    private javax.swing.JTextField txtLogfilePath;
    private javax.swing.JTextField txtRegExp;
    private javax.swing.JTextArea txtReportArea;
    // End of variables declaration//GEN-END:variables
}