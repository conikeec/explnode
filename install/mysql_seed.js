const config = require('../config');
const mysql = require('mysql');
const faker = require('faker');


module.exports.run = function () {
    const connection = mysql.createConnection({
        host: config.MYSQL_HOST,
        port: config.MYSQL_PORT,
        user: config.MYSQL_USER,
        password: config.MYSQL_PASSWORD,
        database: config.MYSQL_DB_NAME
    });

    connection.connect();

    let createAdminsTable = `CREATE TABLE IF NOT EXISTS admins(
        id INT AUTO_INCREMENT PRIMARY KEY,
        type VARCHAR(255) NOT NULL,
        name VARCHAR(255) NOT NULL,
        email VARCHAR(255) NOT NULL,
        password VARCHAR(255) NOT NULL
    ) ENGINE=INNODB;`;

    let createUsersTable = `CREATE TABLE IF NOT EXISTS users(
        id INT AUTO_INCREMENT PRIMARY KEY,
        type VARCHAR(255) NOT NULL,
        name VARCHAR(255) NOT NULL,
        email VARCHAR(255) NOT NULL,
        password VARCHAR(255) NOT NULL
    ) ENGINE=INNODB;`;

    connection.query(createAdminsTable);
    connection.query(createUsersTable);

    //seeder
    for (let index = 1; index < 10; index++) {
        connection.query('INSERT INTO admins SET ?', {
            id: index,
            type: "admin",
            name: faker.name.findName(),
            email: faker.internet.email(),
            password: faker.internet.password(),
        });
    }

    for (let index = 1; index < 10; index++) {
        connection.query('INSERT INTO users SET ?', {
            id: index,
            type: "user",
            name: faker.name.findName(),
            email: faker.internet.email(),
            password: faker.internet.password(),
        });
    }

    connection.end();

}