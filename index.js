const express = require('express')
const bodyParser = require('body-parser');

const app = express()
const port = 3000

app.set('view engine', 'ejs'); //for template injection
app.use(bodyParser.json());

app.get('/', (req, res) => res.send('Hello World!'))

app.use('/xss', require('./vulnerabilities/xss'));
app.use('/sqli', require('./vulnerabilities/sqli'));
app.use('/nosqli', require('./vulnerabilities/nosqli'));
app.use('/exec', require('./vulnerabilities/exec'));
app.use('/loop', require('./vulnerabilities/loop'));
app.use('/redos', require('./vulnerabilities/redos'));
app.use('/xxe', require('./vulnerabilities/xxe'));
app.use('/ssrf', require('./vulnerabilities/ssrf'));


app.listen(port, () => console.log(`Example app listening at http://localhost:${port}`))