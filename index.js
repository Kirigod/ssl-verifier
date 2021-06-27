const https = require("https");


const analyzer = {
    String: (string, replace) => {
        
        if(string.length === 0){
            
            return replace;
        
        }else{
            
            return string;
        
        };
    
    },
    OCSP: (cert) => {
        try{
            
            const _OCSP = cert.infoAccess["OCSP - URI"];
            
            return _OCSP;
        
        }catch{
            
            return [ undefined ];
        
        };
    },
    CA: (cert) => {
        try{
            
            const _CA = cert.infoAccess["CA Issuers - URI"];
            
            if(_CA[0].endsWith("/")) return [ undefined ];
            
            return _CA;
        
        }catch{
            
            return [ undefined ];
        
        };
    },
    inputs: {
        Port: (port) => {
            
            return !isNaN(parseFloat(port)) && Math.sign(port) === 1 && typeof(port) === "number";
        
        },
        Method: (method) => {
            
            if(method === "GET" || method === "HEAD") return true;
            if(method !== "GET" && method !== "HEAD") return false;
    
        },
        check: {
            Options: (input) => {

                let output = {};

                if(input?.method) output.method = input.method;
                if(input?.port) output.port = input.port;
    
                return output;
    
            }
        }
    }
};

function getDaysRemaining(validFrom, validTo){
    
    const daysRemaining = Math.round(Math.abs(+validFrom - +validTo) / 8.64e7);//DaysBetween;

    if(new Date(validTo).getTime() < new Date().getTime()){

        return -daysRemaining;

    };

    return daysRemaining;
    
};

const default_options = {
    agent: new https.Agent({
        maxCachedSessions: 0
    }),
    method: "GET",
    port: 443,
    path: "/",
    rejectUnauthorized: false
};


function Info(inputURL, options){
    
    return new Promise((resolve, reject) => {

        try{
            
            if(!inputURL || typeof(inputURL) !== "string") return reject(new Error("Invalid url"));

            const _URL = new URL(inputURL);
            
            if(_URL.protocol !== "http:" && _URL.protocol !== "https:") return reject(new Error("Invalid protocol"));
            
            if(!!options === true && Object.prototype.toString.call(options) !== "[object Object]") return reject(new Error("Invalid options"));
        
            options = Object.assign({}, default_options, analyzer.inputs.check.Options(options));
            
            if(analyzer.inputs.Method(options.method) !== true) return reject(new Error("Invalid method"));

            if(analyzer.inputs.Port(options.port) !== true) return reject(new Error("Invalid port"));

            
            const request = https.request(Object.assign(options, {host: _URL.host}), (response) => {
                
                const SSL = response.socket.getPeerCertificate();

                if(!SSL.valid_from || !SSL.valid_to || !SSL.subjectaltname) return reject(new Error("No certificate"));

                response.on("data", data => {});

                response.on("end", () => {

                    const _SSL = {
                        subject: {
                            commonName: SSL.subject?.CN,
                            organization: SSL.subject?.O,
                            location: analyzer.String([SSL.subject?.L, SSL.subject?.ST, SSL.subject?.C].filter(item => item !== undefined).join(", "), undefined)
                        },
                        issuer: {
                            commonName: SSL.issuer?.CN,
                            organization: SSL.issuer?.O,
                            location: analyzer.String([SSL.issuer?.L, SSL.issuer?.ST, SSL.issuer?.C].filter(item => item !== undefined).join(", "), undefined)
                        },
                        subjectAlternativeName: SSL.subjectaltname.replace(/DNS:|IP Address:/g, "").split(", "),
                        valid: response.socket.authorized || false,
                        validFrom: SSL.valid_from,
                        validTo: SSL.valid_to,
                        daysRemaining: getDaysRemaining(new Date(), new Date(SSL.valid_to)),
                        certificate: {
                            OCSP: {
                                url: analyzer.OCSP(SSL)
                            },
                            CA:{
                                issuers: {
                                    url: analyzer.CA(SSL)
                                }
                            }
                        },
                        bits: SSL.bits,
                        modulus: SSL.modulus,
                        exponent: SSL.exponent,
                        publicKey: SSL.pubkey,
                        asn1Curve: SSL.asn1Curve,
                        nistCurve: SSL.nistCurve,
                        fingerPrint: SSL.fingerprint,
                        fingerPrint256: SSL.fingerprint256,
                        ExtendedKeyUsage: SSL.ext_key_usage,
                        serialNumber: SSL.serialNumber,
                        raw: SSL.raw
                    };

                    return resolve(_SSL);

                });

            });

            request.on("error", error => {

                return reject(new Error(error.code));

            });

            request.on("timeout", () => {

                request.destroy();
                return reject(new Error("Timed Out"));

            });

            request.end();

        }catch(error){

            return reject(new Error(error.code));

        };

    });

};


module.exports.Info = Info;