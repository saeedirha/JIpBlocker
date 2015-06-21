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
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */
package jipblocker;

import java.awt.Component;
import java.net.URISyntaxException;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.swing.JLabel;
import javax.swing.JTable;
import javax.swing.table.DefaultTableCellRenderer;

/**
 *
 * @author SaEeD
 * Render class to show flags in JTable
 */

public class MyCellRenderer extends DefaultTableCellRenderer { 

@Override
    public Component getTableCellRendererComponent (JTable table,
                                                    Object value,
                                                    boolean isSelected,
                                                    boolean hasFocus,
                                                    int row, int column) {
        if(isSelected) {
            this.setBackground(table.getSelectionBackground());
            this.setForeground(table.getSelectionForeground());
            //System.out.println("MESSAGE FROM RENDERED");
        }else {
            this.setBackground(table.getBackground());
            this.setForeground(table.getForeground());
        }
        
        if (value !=null) {            
                //
                //setText(value.toString());                
                CountryFlag flag = new CountryFlag(value.toString());
            try {
                setIcon(flag.getImage());
            } catch (URISyntaxException ex) {
                Logger.getLogger(MyCellRenderer.class.getName()).log(Level.SEVERE, null, ex);
            }
                
            }else {
                setText((value == null) ? "" : value.toString());
                setIcon(null);
            }
        
        setHorizontalAlignment(JLabel.CENTER);
        return this;
    }
} 