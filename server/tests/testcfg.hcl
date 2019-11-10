SecretKey = "omg123"
AlertMethod = "log"
#ListenAddress = "0.0.0.0:50000"
ListenAddress = "127.0.0.1:50000"

Client "client1" {
    Required = true
    Interval = 5

    Deluge {
        URL = "http://127.0.0.1:8112/json"
        Password = "password"
        MaxTorrents = 5
    }    

    Loadavg {
        MaxLoad = 2.0
    }

    Process = [
        { Path = "/usr/lib/firefox/firefox" User = "username" },
        { Path = "deluge-gtk" }
    ]

    GetUrl { Url = "http://google.com" }
    GetUrl { Url = "https://some-site.com/health" ExpectedBody = "{\"alive\": true}" }
    
    Diskspace { Partition = "/" MaxUsage = 90.0 }

    Diskspace { Partition = "/media/storage" MinFreeGb = 20 }

    Memory {
        MaxUsage = 20.0
    }     

}

Client "client2" {
    Interval = 5

    Memory {
        MaxUsage = 15.0
    }     

    Loadavg {
        MaxLoad = 6.0
    }

    Diskspace = [
        { Partition = "/" MaxUsage = 100.0 }
    ]

}

Client "client3" {
    Memory {
        MaxUsage = 15.0
    } 
}
