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

import java.net.URISyntaxException;
import javax.swing.ImageIcon;

/**
 * This class returns Countries Flags by their name 
 */
public class CountryFlag {
    
    private String CountryName;
    private final String path = "resource/24/";
    public CountryFlag(String CountryName)
    {
       this.CountryName = CountryName;
    // System.out.println("Looking for Flag:" + this.CountryName);
    }
    
    public ImageIcon getImage() throws URISyntaxException
    {
        try{
            ImageIcon icon = new ImageIcon( getClass().getClassLoader().getResource(path + CountryName + ".png"));
            return icon;
        }catch(Exception e)
        {
            System.out.println("[!]Exception Could not find the Flag: " + e.getMessage());
        }
        return null;
    }
    
    
}
