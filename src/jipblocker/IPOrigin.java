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

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.URL;
import java.net.URLConnection;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JTable;
import javax.swing.SwingWorker;

/**
 *
 * @author SaEeD
 */
public class IPOrigin extends SwingWorker<Void, Object>{
    
    
    private JTable table = null;
    
    private final String IPLocatorHost ="http://104.131.173.122/xml/"; //http://whatismyipaddress.com/ip/" and "http://freegeoip.net/xml/"
    
    public IPOrigin(JTable table)
    {
        System.out.println("[+]Creating Thread...");
        this.table = table;
    }
    

// Method to get County name by ip address and flag icons assinged to it
    public String getCountryName(String ip)
    {
        try {
            System.out.println("[*]Thread method called...");
            String address = IPLocatorHost + ip;
            
            URL url = new URL(address);
            URLConnection connection = url.openConnection();
            connection.setConnectTimeout(5*1000);
            BufferedReader stdin = new BufferedReader(new InputStreamReader(connection.getInputStream()));
            
            String input;
            while((input = stdin.readLine()) != null )
            {
                System.out.println(input);
                if(input.contains("CountryName"))
                {
                    
                    String Pattern = "<CountryName>";
                    
                    String [] temp = input.split(Pattern);
                    String CountryName = temp[1].substring(0, temp[1].indexOf("<"));
                    //JOptionPane.showMessageDialog(null, CountryName);
                    
                    if(CountryName.isEmpty())
                    {
                        return "NOT FOUND";
                    }                        
                    
                    return CountryName;
                }
                
            }
            stdin.close();
            
            
        } catch (Exception ex) {
            frmMain.lblStatus.setText("[!]Exception from Accessing the URL: " + ex.getMessage());
            return "Unknown";
        }
        
        return "Unknown";
    }

    @Override
    protected Void doInBackground() throws Exception {
        
        
        frmMain.btnLocate.setEnabled(false);
        table.setAutoCreateRowSorter(false);
        //This would make sure if the sorting changes the order of the rows
        //still we get the correct row value after sorting
        int rowIndex = table.getSelectedRow();
        int row;
        if(rowIndex == -1)
        {
            row = table.convertRowIndexToModel(0);
        }else{
            row = table.convertRowIndexToModel(rowIndex);
        }
        table.setRowSelectionInterval(row, row);
        //////////////////////////////////////////////////
        for(int i=0; i < table.getRowCount(); i++)
            {
                
                table.setValueAt("Looking up, Please wait", i, 2);
                String Origin = getCountryName((String)table.getValueAt(i, 0));
                table.setValueAt(Origin, i, 2);  
                table.setValueAt(Origin, i, 3);
                                
                Thread.sleep(2*1000);
            }
        
        return null;
    }
    
    @Override
    protected void done()
    {
        try
        {
           // JOptionPane.showMessageDialog(null, get());
            frmMain.btnLocate.setEnabled(true);
            System.out.println("[!]Worker Done!");
            table.setAutoCreateRowSorter(true);
        }
        catch (Exception e)
        {e.printStackTrace();
        }
    }
}
 