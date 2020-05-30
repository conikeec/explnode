const config = require('../config');
const faker = require('faker');

const MongoClient = require('mongodb').MongoClient;
const url = config.MONGODB_URI;

module.exports.run = function () {


    //seeder
    for (let index = 1; index < 10; index++) {
        MongoClient.connect(url, function (err, db) {
            if (err) throw err;
            var dbo = db.db(config.MONGODB_DB_NAME);
            var myobj = {
                name: faker.name.findName(),
                email: faker.internet.email(),
                password: faker.internet.password()
            };
            dbo.collection("customers").insertOne(myobj, function (err) {
                if (err) throw err;
                console.log("document inserted");
                db.close();
            });
        });
    }

}