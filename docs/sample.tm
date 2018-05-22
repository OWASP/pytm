/* threats = 
Finding: Dataflow not authenticated on web and db with score 8.6
*/
diagram {
boundary Web_Side {
    title = "Web Side"
    function web_server {
        title = "web server"
    }
}
boundary DB_side {
    title = "DB side"
    database database_server {
        title = "database server"
    }
}
    web_server -> database_server {
         operation = "web and db"
         data = "HTTP"
    }
}
