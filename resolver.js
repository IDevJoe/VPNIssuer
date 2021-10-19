/*
    Resolves an IP address into a MAC address for issuing
 */

const {exec} = require('child_process');
const config = require('./config.json');
const dgram = require('dgram');

let cache = {};

function windows(ip) {
    return new Promise((res, rej) => {
        exec('arp -a', (err, stdout, stderr) => {
            let newarp = {};
            let spl = stdout.split('\n');

            let currentint = null;
            let sk1 = false;
            const int_reg = /Interface: (.*) --- (.*)/;
            const rec_reg = /((?:[0-9]{1,3}\.){3}[0-9]{1,3})\s+((?:[0-9a-z]{2}-){5}[0-9a-z]{2})\s+(dynamic|static)/;
            for(let i=0;i<spl.length;i++) {
                let match = spl[i].match(int_reg);
                if(match != null)
                {
                    currentint = match[2];
                    sk1 = true;
                    continue;
                }
                if(sk1) {
                    sk1 = false;
                    continue;
                }
                if(currentint == null) continue;
                let match2 = spl[i].match(rec_reg);
                if(match2 == null) continue;
                newarp[match2[1]] = {mac: match2[2].replace(/-/g, ':'), int: currentint};
            }
            res(newarp[ip]);
        });
    });
}

function linux(ip) {
    return new Promise((res, rej) => {
        exec('ip neigh show', (err, stdout, stderr) => {
            let newarp = {};
            let spl = stdout.split('\n');

            const reg = /((?:[0-9]{1,3}\.){3}[0-9]{1,3}) dev (.*) lladdr ((?:[0-9a-z]{2}:){5}[0-9a-z]{2}) (STALE|REACHABLE)/;
            spl.forEach(e => {
                let match = e.match(reg);
                if(match == null) return;
                newarp[match[1]] = {mac: match[3], int: match[2]};
            });
            res(newarp[ip]);
        });
    });
}

let aou_socket = null;
let aou_queue = [];
let aou_sent = {};
function aou_init() {
    if(aou_socket != null) return;
    aou_socket = dgram.createSocket("udp4");
    aou_socket.on("message", (msg, rinfo) => {
        if(rinfo.address !== "127.0.0.1") return;
        let ip_raw = [];
        let mac_raw = [];
        let intf = "";
        for(let i=0;i<10;i++) {
            if(i < 4) {
                ip_raw.push(msg.readUInt8(i));
                continue;
            }
            mac_raw.push(msg.readUInt8(i).toString(16));
        }
        let intlen = msg.readUInt8(10);
        for(let i=11;i<11+intlen;i++) {
            intf += String.fromCharCode(msg.readUInt8(i));
        }
        let ip = ip_raw.join('.');
        let mac = mac_raw.join(':');
        let obj = aou_sent[ip];
        console.log(`Received response for IP ${ip}: ${mac}`);
        if(obj == null) return;
        obj.callbacks.forEach(e => e({mac, int: intf}, null));
        delete aou_sent[ip];
    });
    setInterval(() => {
        while(true) {
            let e = aou_queue.shift();
            if(e === undefined) break;
            if(aou_sent[e.ip] === undefined) aou_sent[e.ip] = {callbacks: [], ttl: Date.now()};
            aou_sent[e.ip].callbacks.push(e.callback);
            aou_sent[e.ip].ttl = Date.now() + 3000;
            let ip_spl = e.ip.split('.');
            let buff = Buffer.alloc(4);
            for(let i=0;i<4;i++) {
                buff.writeUInt8(ip_spl[i], i);
            }
            console.log("Sent packet to resolve MAC for " + e.ip);
            aou_socket.send(buff, 1834, config.mac_resolver.aou_host);
        }
        Object.keys(aou_sent).forEach(e => {
            let x = aou_sent[e];
            if(Date.now() > x.ttl) {
                delete aou_sent[e];
                x.callbacks.forEach(e => {
                    e(null, new Error("AOU request timeout"));
                });
            }
        });
    }, 100);
}

function aou(ip) {
    return new Promise((res, rej) => {
        if(aou_socket == null)
            aou_init();
        aou_queue.push({ip, callback: (mac, err) => {
            if(err) return rej(err);
            res(mac)
            }});
    });
}

function resolve(ip) {
    return new Promise((res, rej) => {
        let promise = null;
        if(cache[ip] !== undefined) {
            if(cache[ip].ttl > Date.now()) return res(cache[ip]);
        }
        switch(config.mac_resolver.type) {
            case "windows":
                promise = windows(ip);
                break;
            default:
            case "linux":
                promise = linux(ip);
                break;
            case "aou":
                promise = aou(ip);
                break;
        }
        promise.then(e => {
            if(e === undefined) return rej("MAC not available.");
            cache[ip] = e;
            cache[ip].ttl = Date.now() + 60 * 5;
            res(e);
        }).catch(ex => rej(ex));
    });
}

module.exports.windows = windows;
module.exports.linux = linux;
module.exports.aou = aou;
module.exports.resolve = resolve;