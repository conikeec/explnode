console.log("TarpitNode| Seeding Databases");

console.log("TarpitNode| 1. Seeding MongoDB");
require('./mongo_seed').run();

console.log("TarpitNode| 2. Seeding MySQL");
require('./mysql_seed').run();
console.log("TarpitNode| Installation Done, You can start testing now");