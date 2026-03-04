const https = require('https');
const http = require('http');
const { URL } = require('url');
const config = require('../config');

function sapoAPI(method, endpoint, data = null) {
    return new Promise((resolve, reject) => {
        const baseUrlString = config.SAPO_URL || process.env.SAPO_URL;
        if (!baseUrlString) {
            return reject(new Error('SAPO_URL chưa được cấu hình trong biến môi trường (.env).'));
        }

        // Sử dụng Basic Authentication: apikey:apisecret
        const apiKey = config.SAPO_API_KEY || process.env.SAPO_API_KEY;
        const apiSecret = config.SAPO_API_SECRET || process.env.SAPO_API_SECRET;

        if (!apiKey || !apiSecret) {
            return reject(new Error('SAPO_API_KEY / SAPO_API_SECRET chưa được cấu hình trong biến môi trường (.env).'));
        }

        let baseUrl;
        try {
            baseUrl = new URL(baseUrlString);
        } catch (e) {
            return reject(new Error(`SAPO_URL không hợp lệ: ${e.message}`));
        }

        const isHttps = baseUrl.protocol === 'https:';
        const httpModule = isHttps ? https : http;
        const path = endpoint.startsWith('/') ? endpoint : `/${endpoint}`;

        const options = {
            hostname: baseUrl.hostname,
            port: baseUrl.port || (isHttps ? 443 : 80),
            path: `${baseUrl.pathname.replace(/\/$/, '')}${path}`,
            method: method,
            headers: {
                'Content-Type': 'application/json',
                'Accept': 'application/json',
                'Authorization': 'Basic ' + Buffer.from(`${apiKey}:${apiSecret}`).toString('base64')
            }
        };

        let body = null;
        if (data && (method === 'POST' || method === 'PUT' || method === 'PATCH')) {
            body = JSON.stringify(data);
            options.headers['Content-Length'] = Buffer.byteLength(body);
        }

        const req = httpModule.request(options, (res) => {
            let responseData = '';

            res.on('data', (chunk) => {
                responseData += chunk;
            });

            res.on('end', () => {
                if (!responseData) {
                    return resolve({ statusCode: res.statusCode, data: null });
                }

                try {
                    const parsed = JSON.parse(responseData);
                    if (res.statusCode >= 200 && res.statusCode < 300) {
                        resolve({ statusCode: res.statusCode, data: parsed });
                    } else {
                        reject(new Error(`Sapo API error ${res.statusCode}: ${JSON.stringify(parsed).substring(0, 300)}`));
                    }
                } catch (e) {
                    reject(new Error(`Không parse được JSON từ Sapo (status ${res.statusCode}): ${e.message}. Raw: ${responseData.substring(0, 300)}`));
                }
            });
        });

        req.on('error', (err) => {
            reject(new Error(`Lỗi kết nối Sapo: ${err.message}`));
        });

        if (body) {
            req.write(body);
        }

        req.end();
    });
}

module.exports = {
    sapoAPI
};

