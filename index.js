const express = require('express');
const resolver = require('./resolver');
const issuer = require('./issuer');
const config = require('./config.json');
const fs = require('fs');

let exp = new express();

exp.get('/', (req, res) => {
    let ip = req.ip;
    resolver.resolve(ip).then(e => res.render('home', {mac: e.mac})).catch(e => res.send('Unauthorized from ' + ip));
});

exp.post('/rsp', (req, res) => {
    let ip = req.ip;
    resolver.resolve(ip).then(e => {
        let mac = e.mac;
        issuer.issueCert(mac).then(cert => {
            let c = [
                'client',
                'dev tun',
                'key-direction 1',
                'proto udp',
                `remote ${config.remote_ip} ${config.remote_port}`,
                'resolv-retry infinite',
                'nobind',
                'persist-tun',
                'persist-key',
                '<ca>',
                fs.readFileSync(config.ca_cert),
                '</ca>',
                '<cert>',
                cert.cert,
                '</cert>',
                '<key>',
                cert.key,
                '</key>',
                '<tls-crypt>',
                fs.readFileSync(config.tls_key),
                '</tls-crypt>',
                'cipher AES-256-CBC',
                'comp-lzo',
                'verb 3'
            ].join('\n');
            res.header("Content-Type", "text/plain")
                .header("Content-Disposition", "attachment; filename=\"config.ovpn\"").send(c);
        });
    }).catch(e => {
        console.error(e);
        res.send("Error")
    });
});

exp.set('view engine', 'pug');
exp.set('views', './html');

console.log("Now listening.");
exp.listen(8000);