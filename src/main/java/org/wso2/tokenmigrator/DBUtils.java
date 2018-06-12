/*
 *  Copyright (c) 2018, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 */

package org.wso2.tokenmigrator;

import org.wso2.tokenmigrator.Entities.DBConfigs;

import java.io.File;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLClassLoader;
import java.sql.*;


/**
 * Database related operations.
 */
public class DBUtils {

    private Connection databaseconnection;

    /**
     * initilizing database
     * @param configs connection related parameters.
     */
    public DBUtils(DBConfigs configs) {
        try {
            // Loading the jar file specified in xml file.
            File file = new File(configs.jarlocation);
            URL u = file.toURI().toURL();
            URLClassLoader ucl = new URLClassLoader(new URL[] { u });
            Driver d = (Driver)Class.forName(configs.driverclass, true, ucl).newInstance();
            DriverManager.registerDriver(new DriverShim(d));
        } catch (ClassNotFoundException e) {
            System.out.println("Invelid driver");
            e.printStackTrace();
        } catch (IllegalAccessException e) {
            e.printStackTrace();
        } catch (InstantiationException e) {
            e.printStackTrace();
        } catch (SQLException e) {
            e.printStackTrace();
        } catch (MalformedURLException e) {
            e.printStackTrace();
        }
        try {
            System.out.println("Connecting To Database");
            databaseconnection = DriverManager.getConnection(
                    configs.url,
                    configs.username,
                    configs.password);
            System.out.println("Connected To Database");
        } catch (SQLException e) {
            System.out.println("Invalid database connection attempt.");
            e.printStackTrace();
        }
    }

    /**
     * update tokens.
     * @param tableName table updating
     * @param columnName token containing column
     * @param newValue new token encded with new algorhythm
     * @param currentValue current token going to replace
     * @return is table updated
     */
    public int updateTable(String tableName, String columnName, String newValue, String currentValue) {
        try {
            PreparedStatement updatestatement = databaseconnection.prepareStatement(
                    "UPDATE " + tableName + " SET " + columnName + "= ? WHERE " + columnName + " = ?");
            updatestatement.setString(1, newValue);
            updatestatement.setString(2, currentValue);
            int temp = updatestatement.executeUpdate();
            databaseconnection.commit();
            return temp;
        } catch (SQLException e) {
            System.out.println("Unable To update the table");
            e.printStackTrace();
            return -1;
        }
    }

    /**
     * select all unencoded tokens.
     * @param tableName table updating
     * @param columnName token containing column
     * @return list of tokens
     */
    public ResultSet getTokensInDatabase(String tableName, String columnName) {
        Statement statement = null;
        try {
            statement = databaseconnection.createStatement();
        } catch (SQLException e) {
            System.out.println("Database error");
            e.printStackTrace();
            return null;
        }
        String sql;
        sql = "SELECT " + columnName + " FROM " + tableName;
        try {
            return statement.executeQuery(sql);
        } catch (SQLException e) {
            System.out.printf("Unable to run SQL query");
            e.printStackTrace();
            return null;
        }
    }

    public void closeConnection()
    {
        try {
            this.databaseconnection.close();
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }

}

