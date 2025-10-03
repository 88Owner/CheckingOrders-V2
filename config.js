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
    PORT: process.env.PORT || 3000,
    SESSION_SECRET: required(process.env.SESSION_SECRET, 'Vui lòng thiết lập biến môi trường SESSION_SECRET trong file .env hoặc docker-compose')
};
