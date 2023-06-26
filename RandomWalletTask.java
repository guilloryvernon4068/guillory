package com.zry.wallet;

import lombok.extern.slf4j.Slf4j;
import org.web3j.crypto.CipherException;
import org.web3j.crypto.Credentials;
import org.web3j.crypto.ECKeyPair;
import org.web3j.crypto.Keys;
import org.web3j.protocol.Web3j;
import org.web3j.protocol.core.DefaultBlockParameterName;
import org.web3j.protocol.core.methods.response.EthGetBalance;
import org.web3j.protocol.http.HttpService;
import org.web3j.utils.Convert;
import org.web3j.utils.Numeric;

import java.math.BigDecimal;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.ExecutionException;

@Slf4j
public class RandomWalletTask implements Runnable{

    private List<String> providers = Arrays.asList("https://rpc.ankr.com/eth", "https://rpc.ankr.com/bsc"
            , "https://rpc.ankr.com/arbitrum", "https://rpc.ankr.com/polygon", "https://rpc.ankr.com/optimism");

    private boolean isLuckAddress(String address) {
        if (address.endsWith("000000") || address.endsWith("111111") || address.endsWith("222222")
                || address.endsWith("333333") || address.endsWith("444444") || address.endsWith("555555")
                || address.endsWith("666666") || address.endsWith("777777") || address.endsWith("888888")
                || address.endsWith("999999")) {
            return true;
        }
        return false;
    }

    @Override
    public void run() {

        long count = 0;
        String privateKey;
        Credentials credentials;
        Web3j web3j;
        EthGetBalance ethGetBalance;
        BigInteger weiBalance;


        while (true) {
            try {

                if (count % 50 == 0) {
                    log.info("count={}", count);
                }

                privateKey = createNewWallet();
                credentials = Credentials.create(privateKey);

                if (isLuckAddress(credentials.getAddress())) {
                    log.info("luck address, address={}", credentials.getAddress());
                    log.info("privateKey={}", privateKey);
                }


                for (String provider : providers) {
                    web3j = Web3j.build(new HttpService(provider));
                    ethGetBalance = web3j.ethGetBalance(credentials.getAddress(), DefaultBlockParameterName.LATEST).sendAsync().get();
                    weiBalance = ethGetBalance.getBalance();
                    if (weiBalance.compareTo(new BigInteger("0")) > 0) {
                        log.info("weiBalance={}", weiBalance);
                        log.info("provider={}", provider);
                        log.info("privateKey={}", privateKey);
                    }
                }

                count++;
            } catch (Exception e) {
                log.error("Failed", e);
            }
        }
    }

    public static String createNewWallet() throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException {

        // Generate a new private key
        ECKeyPair ecKeyPair = Keys.createEcKeyPair();

        // Get the private key as a hex string
        String privateKey = Numeric.toHexStringNoPrefix(ecKeyPair.getPrivateKey());

        // Return the private key for the new wallet
        return privateKey;

    }
}
