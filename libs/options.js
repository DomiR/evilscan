var net = require('net');
var cidr = require('./cidr');
var dns = require('dns');
var async = require('async');
var path = require('path');

var getTargets = function(target,cb) {

    if (!target) {
        return cb("Please specify at least a target [cidr|ipv4|host], example:\nevilscan 192.168.0.0/24 --port=21,22,23,80,5900-5910");
    }

    var ips = [];

    async.series([
        function(next) {
            if (target.match(/[a-z]/i) && !target.match(/\//) && !net.isIPv6(target)) {
                dns.resolve4(target,next);
            } else {
                next(null,[[target]]);
            }
        }
    ],function(err,result) {
        if (err) {
            if (err.code=='ENOTFOUND') {
                return cb('Could not resolve '+target);
            }
            return cb(err);
        }

        target = result[0][0]+'';

        if (target.match(/\-/)) {
            var splitTarget = target.split('-'),
                minHost     = splitTarget[0],
                ips         = [],
                splitMinHost, maxHost;

            if (net.isIPv4(minHost)) {
                splitMinHost = minHost.split('.');
                if (net.isIPv4(splitTarget[1])) {
                    maxHost = splitTarget[1].split('.')[3];
                } else {
                    // Check if the string is a positive integer
                    if (splitTarget[1] >>> 0 === parseFloat(splitTarget[1])) {
                        maxHost = splitTarget[1];
                    } else {
                        return cb("Invalid IPv4 target range, ie: 192.168.0.1-5, 192.168.0.1-192.168.0.5");
                    }
                }
            } else {
                return cb("Invalid IPv4 target. ie: 192.168.0.1-5, 192.168.0.1-192.168.0.5");
            }

            for (i = parseInt(splitMinHost[3]); i <= parseInt(maxHost); i++) {
                ips.push(splitMinHost[0] + '.' + splitMinHost[1] + '.' +
                         splitMinHost[2] + '.' + i);
            }

            if (!ips) {
                return cb("Invalid IPv4 target. Please specify a target using --target [cidr|ip|range]");
            }
            return cb(null,ips);
        }

        if (target.match(/\//)) {
            var ips = cidr.get(target);
            if (!ips) {
                return cb("Invalid IPv4 CIDR target. Please specify a target using --target [cidr|ip|range]");
            }
            return cb(null,ips);
        }

        if (net.isIPv6(target)) {
            return cb("IPv6 not supported");
        }

        if (target == '127.0.0.1') {
            return cb(null,[target]);
        }

        if (!net.isIPv4(target)) {
            return cb("Target "+target+" is not a valid IPv4");
        } else {
            return cb(null,[target]);
        }

        return cb("Target: unknow error");
    });
};


var addPortRange = function(range,ports) {
    if (!range.match(/[0-9]+\-[0-9]+/)) return;
    var sp = range.split('-');
    var start = parseInt(sp[0]);
    var end = parseInt(sp[1]);
    if (start+1 && end+1) {
        if (start == 0) start++;
        for (var i = start;i<=end;i++) {
            ports.push(i);
        }
    }
    return true;
};

var getPorts = function(port,cb) {
    var ports = [];

    if (!port) {
        return cb(null,[0]);
    }

    port+='';
    if (port.match(/^[0-9]+$/)) {
        return cb(null,[parseInt(port)]);
    }

    if (!port.match(/[0-9,\-]+/)) {
        return cb("Invalid port "+port);
    }

    port+=',';

    var p = port.split(',');
    p.forEach(function(port) {
        if (!port) return;
        if (!addPortRange(port,ports)) {
            ports.push(parseInt(port));
        }
    });

    if (ports.length) return cb(null,ports);

    return cb('Port: unknow error');
};

var defaultValues = function(argv) {
    if (!argv.concurrency) {
        argv.concurrency = 500;
    }

    if (!argv.timeout) {
        argv.timeout = 2000;
    }

    if (!argv.status) {
        argv.status = 'O';
    }

    if (argv.status.match(/T/)) {
        argv.showTimeout = true;
    }

    if (argv.status.match(/R/)) {
        argv.showRefuse = true;
    }

    if (argv.status.match(/O/)) {
        argv.showOpen = true;
    }

    if (argv.status.match(/U/)) {
        argv.showUnreachable = true;
    }

    if (!argv.scan) {
        argv.scan = 'tcpconnect';
    }

    if (argv.json) {
        argv.display = 'json';
    }

    if (argv.xml) {
        argv.display = 'xml';
    }

    if (argv.console) {
        argv.display = 'console';
    }

    if (!argv.display) {
        argv.display = 'console';
    }

    if (argv.display == 'console') {
        argv.console = true;
    }

    if (argv.display == 'json') {
        argv.json = true;
    }

    if (argv.display == 'xml') {
        argv.xml = true;
    }

    if (!argv.timeout) {
        argv.timeout = 2000;
    }
    return argv;
};


var parse = function(args,cb) {
    args = defaultValues(args);

    async.series([
        function(next) {
            getTargets(args.target,next);
        },
        function(next) {
            getPorts(args.port,next);
        }
    ],function(err,result) {

        if (err) return cb(err);

        args.ips = result[0];
        args.ports = result[1];

        if (!args.port && !args.reverse && !args.geo) {
            var msg = 'Please specify at least one port, --port=80';
            return cb(msg);
        }

        cb(null,args);
    });
};


module.exports = {
    getTargets:getTargets,
    getPorts:getPorts,
    parse:parse
};
