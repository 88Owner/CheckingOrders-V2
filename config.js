// Cấu hình MongoDB và server
const path = require('path');
// Load .env từ cùng thư mục với file config.js để tránh phụ thuộc vào working directory
require('dotenv').config({ path: path.join(__dirname, '.env') });

const required = (value, message) => {
    if (value === undefined || value === null || String(value).length === 0) {
        throw new Error(message);
    }
    return value;
};

module.exports = {
    MONGODB_URI: required(process.env.MONGODB_URI, 'Vui lòng thiết lập biến môi trường MONGODB_URI trong file .env hoặc docker-compose'),
    PORT: process.env.PORT || 30011,
    SESSION_SECRET: required(process.env.SESSION_SECRET, 'Vui lòng thiết lập biến môi trường SESSION_SECRET trong file .env hoặc docker-compose'),
    OPERATIONS_APP_URL: process.env.OPERATIONS_APP_URL || 'https://roots-harvey-transform-meant.trycloudflare.com',
    // ERPNext Configuration
    ERPNEXT_URL: process.env.ERPNEXT_URL || 'http://localhost:8080',
    ERPNEXT_API_KEY: process.env.ERPNEXT_API_KEY || '7da6579c83ee8ff',
    ERPNEXT_API_SECRET: process.env.ERPNEXT_API_SECRET || '406e4001191ddc0',
    // Sapo Configuration
    SAPO_URL: process.env.SAPO_URL || '',
    SAPO_ACCESS_TOKEN: process.env.SAPO_ACCESS_TOKEN || '',
    // Backward-compatible keys (some setups used API_KEY/API_SECRET)
    SAPO_API_KEY: process.env.SAPO_API_KEY || '',
    SAPO_API_SECRET: process.env.SAPO_API_SECRET || '',
    SAPO_PURCHASE_ORDER_ENDPOINT: process.env.SAPO_PURCHASE_ORDER_ENDPOINT || '',
    // Receive inventory defaults
    SAPO_LOCATION_ID: process.env.SAPO_LOCATION_ID || '',
    SAPO_SUPPLIER_ID: process.env.SAPO_SUPPLIER_ID || '',
    SAPO_ASSIGNEE_ID: process.env.SAPO_ASSIGNEE_ID || '',
    SAPO_RECEIPT_STATUS: process.env.SAPO_RECEIPT_STATUS || 'pending'
};
