const fs = require('fs');
const {exec} = require('child_process');
const path = require('path');
const pem = require('pem');
const config = require('./config.json');

function genKey() {
    return new Promise((res, rej) => {
        pem.createPrivateKey(2048, {}, (err, key) => {
            res(key);
        })
    });
}

function genCsr(key, mac) {
    return new Promise((res, rej) => {
        let mac_ip = mac.replace(/:/g, '.');
        let config = [
            '[req]',
            'req_extensions = v3_req',
            'distinguished_name = req_distinguished_name',
            '[v3_req]',
            'basicConstraints = CA:FALSE',
            'keyUsage = digitalSignature, keyEncipherment',
            'extendedKeyUsage = clientAuth',
            'subjectAltName = @alt_names',
            '[alt_names]',
            'DNS.1 = ' + mac_ip + ".internal.devjoe.net",
            '[req_distinguished_name]',
            'commonName = Common Name',
            'commonName_max = 64'
        ].join('\n');
        pem.createCSR({clientKey: key, keyBitsize: 2048, hash: "SHA256", commonName: `${mac_ip}.internal.devjoe.net`, config: config}, (err, csr) => {
            if(err) return rej(err);
            res(csr);
        });
    })
}

function signCert(ca, cakey, key, csr, csrconf) {
    return new Promise((res, rej) => {
        let cak = fs.readFileSync(cakey);
        let cac = fs.readFileSync(ca);
        pem.createCertificate({serviceCertificate: cac, serviceKey: cak, days: 30, csr: csr, config: csrconf}, (err, cert) => {
            if(err) return rej(err);
            res(cert);
        });
    });
}

async function issueCert(mac) {
    let key = await genKey();
    let csr = await genCsr(key.key, mac);
    let signed = await signCert(config.ca_cert, config.ca_key, key.key, csr.csr, csr.config);
    return {key: key.key, cert: signed.certificate};
}

module.exports.issueCert = issueCert;