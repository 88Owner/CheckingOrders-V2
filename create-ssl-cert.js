// Tạo SSL certificate bằng Node.js
const forge = require('node-forge');
const fs = require('fs');

function createSelfSignedCert() {
    console.log('🔐 Creating self-signed SSL certificate...');
    
    try {
        // Tạo private key
        const keys = forge.pki.rsa.generateKeyPair(2048);
        const privateKey = forge.pki.privateKeyToPem(keys.privateKey);
        
        // Tạo certificate
        const cert = forge.pki.createCertificate();
        cert.publicKey = keys.publicKey;
        cert.serialNumber = '01';
        cert.validity.notBefore = new Date();
        cert.validity.notAfter = new Date();
        cert.validity.notAfter.setFullYear(cert.validity.notBefore.getFullYear() + 1);
        
        const attrs = [{
            name: 'commonName',
            value: '192.168.1.31'
        }, {
            name: 'countryName',
            value: 'VN'
        }, {
            name: 'stateOrProvinceName',
            value: 'HCM'
        }, {
            name: 'localityName',
            value: 'HCM'
        }, {
            name: 'organizationName',
            value: 'OrderCheck'
        }];
        
        cert.setSubject(attrs);
        cert.setIssuer(attrs);
        cert.sign(keys.privateKey);
        
        const certPem = forge.pki.certificateToPem(cert);
        
        // Lưu files
        fs.writeFileSync('server.key', privateKey);
        fs.writeFileSync('server.crt', certPem);
        
        console.log('✅ SSL certificate created successfully');
        return true;
    } catch (error) {
        console.error('❌ Error creating certificate:', error.message);
        return false;
    }
}

// Chạy
if (require.main === module) {
    createSelfSignedCert();
}
