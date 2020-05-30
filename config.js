require('dotenv').config()
module.exports = {
    APP_NAME: process.env.APP_NAME || 'TarpitNodeJs',
    PORT: process.env.PORT || 3000,
    MONGODB_URI: process.env.MONGODB_URI || "mongodb://localhost:27017/",
    MONGODB_DB_NAME: process.env.MONGODB_DB_NAME || "CVNA_DB",
    MYSQL_HOST: process.env.MYSQL_HOST || "localhost",
    MYSQL_PORT: process.env.MYSQL_PORT || "3306",
    MYSQL_USER: process.env.MYSQL_USER || "root",
    MYSQL_PASSWORD: process.env.MYSQL_PASSWORD || "root",
    MYSQL_DB_NAME: process.env.MYSQL_DB_NAME || "CVNA_DB"
}