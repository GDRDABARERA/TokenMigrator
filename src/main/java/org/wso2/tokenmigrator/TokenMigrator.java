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

import org.apache.axiom.om.util.Base64;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.wso2.tokenmigrator.Entities.DBConfigs;
import org.wso2.tokenmigrator.Entities.MigrationConfig;

import java.security.Security;
import java.sql.ResultSet;
import java.util.List;

/**
 * Token migrator class.
 */
public class TokenMigrator {

    private static final Log log = LogFactory.getLog(TokenMigrator.class);

    /**
     * Main methord.
     * @param args command line arguments.
     * @throws Exception When configs are wrong.
     */
    public static void main(String[] args) throws Exception {
        //Security.insertProviderAt(new BouncyCastleProvider(), 1);
        Security.addProvider(new BouncyCastleProvider());
        ConfigFileLoader configFileLoader = new ConfigFileLoader();
        List<MigrationConfig> migrationConfigsList = configFileLoader.getMigrationConfigList();
        DBConfigs databaseConfigs = configFileLoader.getDatabaseConfigs();
        DBUtils dbUtils = new DBUtils(databaseConfigs);
        EncryptDecryptUtils encryptDecryptUtils = new EncryptDecryptUtils(configFileLoader);
        String tempToken;
        String tempDecodedToken;
        byte[] tempEncodeToken;
        int count = 0;
        for (MigrationConfig config:migrationConfigsList) {
            ResultSet listOfTokens = dbUtils.getTokensInDatabase(config.tableName, config.columnName);
            System.out.println("Key migration started for table " + config.tableName + " Column " + config.columnName);
            while (listOfTokens.next()) {
                tempToken = listOfTokens.getString(config.columnName);
                tempDecodedToken = encryptDecryptUtils.decrypt(Base64.decode(tempToken), config.decryptionAlgorhythm);
                tempEncodeToken = encryptDecryptUtils.encrypt(tempDecodedToken, config.encryptionAlgorhythm);
                dbUtils.updateTable(config.tableName, config.columnName, Base64.encode(tempEncodeToken), tempToken);
                count++;
            }
            System.out.println("Key migration finished for table " + config.tableName + " Column " + config.columnName);
            System.out.printf("Total of " + count + " entries migrated");
        }
        dbUtils.closeConnection();
    }
}
