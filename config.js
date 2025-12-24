// Cấu hình MongoDB và server
require('dotenv').config();

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
    // ERPNext Configuration
    ERPNEXT_URL: process.env.ERPNEXT_URL || 'http://localhost:8080',
    ERPNEXT_API_KEY: process.env.ERPNEXT_API_KEY || '7da6579c83ee8ff',
    ERPNEXT_API_SECRET: process.env.ERPNEXT_API_SECRET || '406e4001191ddc0'
};
