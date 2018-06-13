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



    /**
     * Main method.
     * @param args command line arguments.
     * @throws Exception When configs are wrong.
     */
    public static void main(String[] args) throws Exception {

        Security.addProvider(new BouncyCastleProvider());
        ConfigFileLoader configFileLoader = new ConfigFileLoader(args[0]);
        List<MigrationConfig> migrationConfigsList = configFileLoader.getMigrationConfigList();
        DBConfigs databaseConfigs = configFileLoader.getDatabaseConfigs();
        DBUtils dbUtils = new DBUtils(databaseConfigs);
        EncryptDecryptUtils encryptDecryptUtils = new EncryptDecryptUtils(configFileLoader);
        String tempToken;
        String tempDecodedToken;
        byte[] tempEncodeToken;

        for (MigrationConfig config:migrationConfigsList) {
            int loop = 0;
            int count = 0;

            System.out.println("LOG: Key migration started for table " + config.tableName + " Column " + config
                    .columnName);
            while (loop < 2) {
                ResultSet listOfTokens = dbUtils.getTokensInDatabase(config.tableName, config.columnName);
                if (loop == 1) {
                    System.out.println("LOG: migration is successful, Hence putting back to DB \n");
                }
                while (listOfTokens.next()) {
                    tempToken = listOfTokens.getString(config.columnName);

                    tempDecodedToken = encryptDecryptUtils.decrypt(Base64.decode(tempToken), config.decryptionAlgorhythm);
                    tempEncodeToken = encryptDecryptUtils.encrypt(tempDecodedToken, config.encryptionAlgorhythm);

                    if (loop == 1) {
                        System.out.println("LOG : decrypting started for the token : " + tempToken + "\n");
                        System.out.println("LOG: encrypted token to be put to DB back : " + Base64.encode
                                (tempEncodeToken) + "\n");
                        System.out.println("-------------------------------------------");
                        dbUtils.updateTable(config.tableName, config.columnName, Base64.encode(tempEncodeToken),
                             tempToken);
                        count++;
                    }
                }
                loop++;
            }
            System.out.println("LOG: Key migration finished for table " + config.tableName + " Column " + config
                    .columnName);
            System.out.printf("LOG: Total of " + count + " entries migrated");
            System.out.println("=======================================================\n\n");
        }
        dbUtils.closeConnection();
    }
}
