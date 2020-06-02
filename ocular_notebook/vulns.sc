// Startup Ocular REPL 
// -------------------

sl ocular

// create CPG from source 
// ----------------------

importCode("/Users/chetanconikee/pgithub/explnode")

// Apply Policies to graph  
// -----------------------

run.securityprofile

// get AttackSurface of Application
// ---------------------------------

case class AttackSurface(shortMethodName : String, fullMethodName : String, route : String)

def getAttackSurface(cpg: io.shiftleft.codepropertygraph.Cpg) : List[AttackSurface] = {
	cpg.source.method.map { m => 
		AttackSurface(m.name, 
			m.fullName, 
			m.tagList.filter(t => t.name == "EXPOSED_METHOD_ROUTE").map(_.value).mkString(""))
	}.l
}

val attackSurface = getAttackSurface(cpg)

// get Exposed Sources in Application (this represents all exposed API endpoints in code)
// --------------------------------------------------------------------------------------

val source = cpg.method.filter(_.tag.name("EXPOSED_METHOD")).parameter

// 1. Remote Code Execution based finding (exec.js)
// --------------------------------------------------------------------------------------

val sink = cpg.method.name(".*spawn.*").parameter

sink.reachableBy(source).flows.p

res8: List[String] = List(
  """ ____________________________________________________________________________
 | tracked       | lineNumber| method               | file                   |
 |===========================================================================|
 | req           | 27        | :=>                  | vulnerabilities/exec.js|
 | req.params.cmd| 28        | :=>                  | vulnerabilities/exec.js|
 | p2            | N/A       | <operator>.assignment|                        |
 | p1            | N/A       | <operator>.assignment|                        |
 | cmd           | 28        | :=>                  | vulnerabilities/exec.js|
 | cmd           | 29        | :=>                  | vulnerabilities/exec.js|
 | cmd           | 32        | runMe                | vulnerabilities/exec.js|
 | cmd           | 35        | runMe                | vulnerabilities/exec.js|
 | p1            | N/A       | spawn                |                        |
"""
)

// 2. Denial of Service Attack (loop.js)
// --------------------------------------------------------------------------------------

cpg.call.code(".*push.*").inAst.isControlStructure.parserTypeName("For.*").code.l 

res31: List[String] = List(
  """for (var i = 0; i < obj.length; i++) {
        someArr.push(obj[i]);
    }""",
  """for (var i = 0; i < obj.length; i++) {
        someArr.push(obj[i]);
    }"""
)

val sink = cpg.call.code(".*push.*").filter(_.inAst.isControlStructure.parserTypeName("For.*"))

sink.reachableBy(source).flows.p

res33: List[String] = List(
  """ ____________________________________________________________________________
 | tracked       | lineNumber| method               | file                   |
 |===========================================================================|
 | req           | 5         | :=>                  | vulnerabilities/loop.js|
 | req.body.users| 6         | :=>                  | vulnerabilities/loop.js|
 | p2            | N/A       | <operator>.assignment|                        |
 | p1            | N/A       | <operator>.assignment|                        |
 | obj           | 6         | :=>                  | vulnerabilities/loop.js|
 | obj[i]        | 11        | :=>                  | vulnerabilities/loop.js|
 | p1            | N/A       | push                 |                        |
 | p0            | N/A       | push                 |                        |
 | someArr       | 11        | :=>                  | vulnerabilities/loop.js|
""",
  """ ____________________________________________________________________________
 | tracked       | lineNumber| method               | file                   |
 |===========================================================================|
 | req           | 5         | :=>                  | vulnerabilities/loop.js|
 | req.body.users| 6         | :=>                  | vulnerabilities/loop.js|
 | p2            | N/A       | <operator>.assignment|                        |
 | p1            | N/A       | <operator>.assignment|                        |
 | obj           | 6         | :=>                  | vulnerabilities/loop.js|
 | obj[i]        | 11        | :=>                  | vulnerabilities/loop.js|
 | p1            | N/A       | push                 |                        |
 | p0            | N/A       | push                 |                        |
 | someArr       | 11        | :=>                  | vulnerabilities/loop.js|
"""
)


// 3. NoSql  Injection (nosqli.js)
// --------------------------------------------------------------------------------------

val sink = cpg.method.name(".*insertOne.*").parameter

sink.reachableBy(source).flows.p

res14: List[String] = List(
  """ __________________________________________________________________________________________________________________
 | tracked                                           | lineNumber| method               | file                     |
 |=================================================================================================================|
 | req                                               | 8         | :=>                  | vulnerabilities/nosqli.js|
 | req.body.name                                     | 18        | :=>                  | vulnerabilities/nosqli.js|
 | p2                                                | N/A       | <operator>.assignment|                          |
 | p1                                                | N/A       | <operator>.assignment|                          |
 | _tmp_3.name                                       | 18        | :=>                  | vulnerabilities/nosqli.js|
 | { name: req.body.name, address: req.body.address }| 18        | :=>                  | vulnerabilities/nosqli.js|
 | p2                                                | N/A       | <operator>.assignment|                          |
 | p1                                                | N/A       | <operator>.assignment|                          |
 | myobj                                             | 18        | :=>                  | vulnerabilities/nosqli.js|
 | myobj                                             | 19        | :=>                  | vulnerabilities/nosqli.js|
 | p1                                                | N/A       | insertOne            |                          |
""",
  """ __________________________________________________________________________________________________________________
 | tracked                                           | lineNumber| method               | file                     |
 |=================================================================================================================|
 | req                                               | 8         | :=>                  | vulnerabilities/nosqli.js|
 | req.body.address                                  | 18        | :=>                  | vulnerabilities/nosqli.js|
 | p2                                                | N/A       | <operator>.assignment|                          |
 | p1                                                | N/A       | <operator>.assignment|                          |
 | _tmp_3.address                                    | 18        | :=>                  | vulnerabilities/nosqli.js|
 | { name: req.body.name, address: req.body.address }| 18        | :=>                  | vulnerabilities/nosqli.js|
 | p2                                                | N/A       | <operator>.assignment|                          |
 | p1                                                | N/A       | <operator>.assignment|                          |
 | myobj                                             | 18        | :=>                  | vulnerabilities/nosqli.js|
 | myobj                                             | 19        | :=>                  | vulnerabilities/nosqli.js|
 | p1                                                | N/A       | insertOne            |                          |
"""
)

// 4. Redirect (redirect.js) SSRF
// --------------------------------------------------------------------------------------

val sink = cpg.method.name(".*redirect.*").parameter

sink.reachableBy(source).flows.p

res15: List[String] = List(
 """ ____________________________________________________________________________________________________
 | tracked                           | lineNumber| method               | file                       |
 |===================================================================================================|
 | req                               | 6         | :anonymous           | vulnerabilities/redirect.js|
 | req.query.path                    | 7         | :anonymous           | vulnerabilities/redirect.js|
 | p2                                | N/A       | <operator>.assignment|                            |
 | p1                                | N/A       | <operator>.assignment|                            |
 | followPath                        | 7         | :anonymous           | vulnerabilities/redirect.js|
 | followPath                        | 9         | :anonymous           | vulnerabilities/redirect.js|
 | p2                                | N/A       | <operator>.addition  |                            |
 | ret                               | N/A       | <operator>.addition  |                            |
 | "http://example.com/" + followPath| 9         | :anonymous           | vulnerabilities/redirect.js|
 | p1                                | N/A       | redirect             |                            |
"""
)


// 5. RegexDOS (redos.js)
// --------------------------------------------------------------------------------------

val sink = cpg.method.name(".*test.*").parameter

sink.reachableBy(source).flows.p
res19: List[String] = List(
  """ _____________________________________________________________
 | tracked      | lineNumber| method| file                    |
 |============================================================|
 | req          | 5         | :=>   | vulnerabilities/redos.js|
 | req.params.id| 8         | :=>   | vulnerabilities/redos.js|
 | p1           | N/A       | test  |                         |
"""
)

// 6. SQL Injection (sqli.js)
// --------------------------------------------------------------------------------------

val sink = cpg.method.fullName(".*query.*").parameter

sink.reachableBy(source).flows.p
res25: List[String] = List(
  """ ____________________________________________________________________________________________________________________________
 | tracked                                                       | lineNumber| method               | file                   |
 |===========================================================================================================================|
 | req                                                           | 16        | :=>                  | vulnerabilities/sqli.js|
 | req.params.id                                                 | 17        | :=>                  | vulnerabilities/sqli.js|
 | p2                                                            | N/A       | <operator>.assignment|                        |
 | p1                                                            | N/A       | <operator>.assignment|                        |
 | userId                                                        | 17        | :=>                  | vulnerabilities/sqli.js|
 | userId                                                        | 19        | :=>                  | vulnerabilities/sqli.js|
 | p2                                                            | N/A       | <operator>.addition  |                        |
 | ret                                                           | N/A       | <operator>.addition  |                        |
 | "SELECT * FROM users WHERE id=" + userId                      | 19        | :=>                  | vulnerabilities/sqli.js|
 | p2                                                            | N/A       | <operator>.assignment|                        |
 | p1                                                            | N/A       | <operator>.assignment|                        |
 | _tmp_1.sql                                                    | 19        | :=>                  | vulnerabilities/sqli.js|
 | {
        sql : "SELECT * FROM users WHERE id=" + userId
    }| 18        | :=>                  | vulnerabilities/sqli.js|
 | p2                                                            | N/A       | <operator>.assignment|                        |
 | p1                                                            | N/A       | <operator>.assignment|                        |
 | query                                                         | 18        | :=>                  | vulnerabilities/sqli.js|
 | query                                                         | 21        | :=>                  | vulnerabilities/sqli.js|
 | p1                                                            | N/A       | query                |                        |
""",
  """ ___________________________________________________________________________________________________________________________
 | tracked                                                      | lineNumber| method               | file                   |
 |==========================================================================================================================|
 | req                                                          | 33        | :=>                  | vulnerabilities/sqli.js|
 | req.params.id                                                | 34        | :=>                  | vulnerabilities/sqli.js|
 | p2                                                           | N/A       | <operator>.assignment|                        |
 | p1                                                           | N/A       | <operator>.assignment|                        |
 | userId                                                       | 34        | :=>                  | vulnerabilities/sqli.js|
 | userId                                                       | 36        | :=>                  | vulnerabilities/sqli.js|
 | p2                                                           | N/A       | <operator>.addition  |                        |
 | ret                                                          | N/A       | <operator>.addition  |                        |
 | "SELECT * FROM users WHERE id=" + userId                     | 36        | :=>                  | vulnerabilities/sqli.js|
 | p2                                                           | N/A       | <operator>.assignment|                        |
 | p1                                                           | N/A       | <operator>.assignment|                        |
 | _tmp_2.sql                                                   | 36        | :=>                  | vulnerabilities/sqli.js|
 | {
        sql : "SELECT * FROM users WHERE id=" +userId
    }| 35        | :=>                  | vulnerabilities/sqli.js|
 | p1                                                           | N/A       | query                |                        |
""",
  """ ______________________________________________________________________________________________________
 | tracked                                 | lineNumber| method               | file                   |
 |=====================================================================================================|
 | req                                     | 26        | :=>                  | vulnerabilities/sqli.js|
 | req.params.id                           | 27        | :=>                  | vulnerabilities/sqli.js|
 | p2                                      | N/A       | <operator>.assignment|                        |
 | p1                                      | N/A       | <operator>.assignment|                        |
 | userId                                  | 27        | :=>                  | vulnerabilities/sqli.js|
 | userId                                  | 28        | :=>                  | vulnerabilities/sqli.js|
 | p2                                      | N/A       | <operator>.addition  |                        |
 | ret                                     | N/A       | <operator>.addition  |                        |
 | "SELECT * FROM users WHERE id=" + userId| 28        | :=>                  | vulnerabilities/sqli.js|
 | p1                                      | N/A       | query                |                        |
"""
)

// 7. Server Side Request Forgery (ssrf.js)
// --------------------------------------------------------------------------------------

// Goal is to find a flow from the req param of handler function of /downlad-url to the request method's first param
// ensuring that its passing through "followAllRedirects: true" option as one of the tracked data:

var source = cpg.method.name(".*=>.*").parameter 

var sink = cpg.method.name(".*request.*").parameter 

ocular> sink.reachableBy(source).flows.passes(_.ast.isCall.code(".*followAllRedirects.*true.*")).p 
res33: List[String] = List(
  """ _________________________________________________________________________________________________________________________________________
 | tracked                                                                    | lineNumber| method               | file                   |
 |========================================================================================================================================|
 | url                                                                        | 11        | :=>                  | vulnerabilities/ssrf.js|
 | url                                                                        | 13        | :=>                  | vulnerabilities/ssrf.js|
 | p2                                                                         | N/A       | <operator>.assignment|                        |
 | p1                                                                         | N/A       | <operator>.assignment|                        |
 | _tmp_0.uri                                                                 | 13        | :=>                  | vulnerabilities/ssrf.js|
 | {
      uri: url,
      method: 'GET',
      followAllRedirects: true
    }| 12        | :=>                  | vulnerabilities/ssrf.js|
 | p2                                                                         | N/A       | <operator>.assignment|                        |
 | p1                                                                         | N/A       | <operator>.assignment|                        |
 | opts                                                                       | 12        | :=>                  | vulnerabilities/ssrf.js|
 | opts                                                                       | 18        | :=>                  | vulnerabilities/ssrf.js|
 | p1                                                                         | N/A       | request              |                        |
"""
)

// 8. Cross Site Scripting (xss.js)
// --------------------------------------------------------------------------------------

val sink = cpg.method.fullName(".*(send|render).*").parameter

sink.reachableBy(source).flows.p
res25: List[String] = List(
""" _____________________________________________________
 | tracked| lineNumber| method| file                  |
 |====================================================|
 | res    | 4         | :=>   | vulnerabilities/xss.js|
 | res    | 6         | :=>   | vulnerabilities/xss.js|
 | p0     | N/A       | send  |                       |
""",
  """ ____________________________________________________________________________________________
 | tracked                        | lineNumber| method               | file                  |
 |===========================================================================================|
 | req                            | 4         | :=>                  | vulnerabilities/xss.js|
 | req.query                      | 5         | :=>                  | vulnerabilities/xss.js|
 | p2                             | N/A       | <operator>.assignment|                       |
 | p1                             | N/A       | <operator>.assignment|                       |
 | _tmp_0                         | 5         | :=>                  | vulnerabilities/xss.js|
 | _tmp_0.name                    | 5         | :=>                  | vulnerabilities/xss.js|
 | p2                             | N/A       | <operator>.assignment|                       |
 | p1                             | N/A       | <operator>.assignment|                       |
 | name                           | 5         | :=>                  | vulnerabilities/xss.js|
 | name                           | 6         | :=>                  | vulnerabilities/xss.js|
 | p2                             | N/A       | <operator>.addition  |                       |
 | ret                            | N/A       | <operator>.addition  |                       |
 | "<h1> Hello :" + name          | 6         | :=>                  | vulnerabilities/xss.js|
 | p1                             | N/A       | <operator>.addition  |                       |
 | ret                            | N/A       | <operator>.addition  |                       |
 | "<h1> Hello :" + name + "</h1>"| 6         | :=>                  | vulnerabilities/xss.js|
 | p1                             | N/A       | send                 |                       |
""")

// 9. XXE (xxe.js)
// --------------------------------------------------------------------------------------

val sink = cpg.call.code(".*parseXmlString.*").code(".*noent:true.*").argument

sink.reachableBy(source).flows.p

res35: List[String] = List(
  """ ____________________________________________________________________________________
 | tracked                | lineNumber| method               | file                  |
 |===================================================================================|
 | req                    | 6         | :=>                  | vulnerabilities/xxe.js|
 | req.files.products.data| 7         | :=>                  | vulnerabilities/xxe.js|
 | p2                     | N/A       | <operator>.assignment|                       |
 | p1                     | N/A       | <operator>.assignment|                       |
 | XMLfile                | 7         | :=>                  | vulnerabilities/xxe.js|
 | XMLfile                | 8         | :=>                  | vulnerabilities/xxe.js|
"""
)

// 9. All Findings based on automated security profile
// --------------------------------------------------------------------------------------

cpg.finding.toJsonPretty


