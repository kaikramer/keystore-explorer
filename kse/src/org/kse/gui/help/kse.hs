<?xml version="1.0" encoding="ISO-8859-1" ?>

<!--=======================================================================
  Copyright 2004 - 2013 Wayne Grant
            2013 - 2018 Kai Kramer
  
  This file is part of KeyStore Explorer.
  
  KeyStore Explorer is free software: you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation, either version 3 of the License, or
  (at your option) any later version.
  
  KeyStore Explorer is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.
  
  You should have received a copy of the GNU General Public License
  along with KeyStore Explorer. If not, see <http://www.gnu.org/licenses/>.
=======================================================================-->


<!DOCTYPE helpset
  PUBLIC "-//Sun Microsystems Inc.//DTD JavaHelp HelpSet Version 1.0//EN"
          "http://java.sun.com/products/javahelp/helpset_1_0.dtd">

<helpset version="2.0">

   <!-- title -->
   <title>KeyStore Explorer Help</title>

   <!-- maps -->
   <maps>
      <homeID>introduction</homeID>
      <mapref location="kseMap.jhm" />
   </maps>

   <!-- views -->
   <view mergetype="javax.help.UniteAppendMerge">
      <name>Contents</name>
      <label>Contents</label>
      <type>javax.help.TOCView</type>
      <data>contents.xml</data>
      <image>contentstab</image>
   </view>

   <view>
      <name>search</name>
      <label>Search</label>
      <type>javax.help.SearchView</type>
      <data engine="com.sun.java.help.search.DefaultSearchEngine">searchindex</data>
      <image>searchtab</image>
   </view>

   <!-- presentations -->
   <presentation xml:lang="en" default="true" displayviewimages="true">
      <name>Default Presentation</name>
      <image>helpicon</image>
      <toolbar>
         <helpaction image="homebtn">javax.help.HomeAction</helpaction>
         <helpaction image="backbtn">javax.help.BackAction</helpaction>
         <helpaction image="forwardbtn">javax.help.ForwardAction</helpaction>
      </toolbar>
   </presentation>

</helpset>
